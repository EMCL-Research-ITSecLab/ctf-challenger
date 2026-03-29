import random
import subprocess
import threading

from subnet_calculations import nth_network_subnet
from DatabaseClasses import *
from proxmox_api_calls import *
import os
import shlex
from stop_challenge import stop_challenge
from warmup_challenge import warmup_challenge
import time
from dotenv import load_dotenv, find_dotenv
import hashlib
import hmac
from launch_timing_logger import launch_timing_logger
from get_db_connection import run_with_db_connection

load_dotenv(find_dotenv())

CHALLENGES_ROOT_SUBNET = os.getenv("CHALLENGES_ROOT_SUBNET", "10.128.0.0")
CHALLENGES_ROOT_SUBNET_MASK = os.getenv("CHALLENGES_ROOT_SUBNET_MASK", "255.128.0.0")
CHALLENGES_ROOT_SUBNET_MASK_INT = sum(bin(int(x)).count('1') for x in CHALLENGES_ROOT_SUBNET_MASK.split('.'))
CHALLENGES_ROOT_SUBNET_CIDR = f"{CHALLENGES_ROOT_SUBNET}/{CHALLENGES_ROOT_SUBNET_MASK_INT}"
WAZUH_ENROLLMENT_PASSWORD = os.getenv("WAZUH_ENROLLMENT_PASSWORD")

DNSMASQ_INSTANCES_DIR = "/etc/dnsmasq-instances/"
os.makedirs(DNSMASQ_INSTANCES_DIR, exist_ok=True)


challenge_launch_lock_dir = "/var/lock/challenge_launch_locks/"
os.makedirs(challenge_launch_lock_dir, exist_ok=True)

@run_with_db_connection
def launch_challenge(challenge_template_id, user_id, vpn_monitoring_device, dmz_monitoring_device, db_conn=None):
    """
    Launch a challenge by creating a user and network device.
    """



    try:
        launch_lock = acquire_exclusive_launch_lock(user_id)
        start_time = time.time()

        try:
            start_time_db_fetch = time.time()
            print(f"[Info] DB fetch started for user {user_id} and challenge template {challenge_template_id}", flush=True)
            user_vpn_ip = fetch_user_vpn_ip(user_id, db_conn)
            user_unique_id = fetch_user_unique_id(user_id, db_conn)
            challenge_template = ChallengeTemplate(challenge_template_id)
            fetch_challenge_flags(challenge_template, db_conn)

            launch_timing_logger(start_time_db_fetch, "[DB FETCH COMPLETE]", challenge_template_id, user_id)
        except Exception as e:
            raise ValueError(f"Error fetching from database: {e}")

        try:
            print(f"[Info] Attempting to get ready challenge for template {challenge_template_id} and user {user_id}", flush=True)
            challenge = get_ready_challenge(challenge_template, db_conn)
            if challenge is None:
                running_warmup_challenge_id = try_attach_to_running_warmup(challenge_template_id, user_id, db_conn)
                if running_warmup_challenge_id is not None:
                    print(f"[Info] Attached to running warmup challenge {running_warmup_challenge_id} for template {challenge_template_id} and user {user_id}", flush=True)

                    while challenge is None:
                        running_warmup_challenge_id = check_running_warmup(challenge_template_id, user_id, db_conn)
                        if running_warmup_challenge_id is None:
                            break

                        challenge = get_ready_challenge(challenge_template, db_conn, user_id)
                        time.sleep(1)

            if challenge is None:
                print(f"[Info] No ready challenge found and attaching failed, creating new challenge for template {challenge_template_id} and user {user_id}", flush=True)
                challenge = warmup_challenge(user_id, challenge_template.id, vpn_monitoring_device, dmz_monitoring_device)

            print(f"[Info] Adding running challenge {challenge.id} to user {user_id}", flush=True)
            add_running_challenge_to_user(challenge, user_id, db_conn)

            print(f"[Info] Got challenge {challenge.id} for template {challenge_template_id} and user {user_id}", flush=True)
            fetch_machines(challenge, db_conn)

            print(f"[Info] Fetched machines for challenge {challenge.id}", flush=True)
            fetch_networks_and_connections(challenge, db_conn)

        except Exception as e:
            print(f"[Error] Failed to prepare challenge for launch: {e}", flush=True)
            try:
                stop_challenge(user_id)
            except Exception as stop_e:
                print(f"[Error] Failed to stop challenge after error: {stop_e}", flush=True)

            raise ValueError(f"Error creating challenge: {e}")

        try:
            # Network setup
            start_time_network = time.time()
            print(f"[Info] Starting network setup for challenge {challenge.id} and user {user_id}", flush=True)
            start_dnsmasq_instances(challenge, user_vpn_ip)
            launch_timing_logger(start_time_network, "[NETWORK SETUP COMPLETE]", challenge_template_id, user_id)

            start_time_user_flags = time.time()
            print(f"[Info] Starting user-specific flag processing for challenge {challenge.id} and user {user_id}", flush=True)
            process_all_user_specific_flags(challenge, user_unique_id)
            launch_timing_logger(start_time_user_flags, "[USER FLAGS COMPLETE]", challenge_template_id, user_id)

            start_time_firewall = time.time()
            print(f"[Info] Starting iptables rule setup for challenge {challenge.id} and user {user_id}", flush=True)
            add_iptables_rules(challenge, user_vpn_ip, vpn_monitoring_device, dmz_monitoring_device)
            launch_timing_logger(start_time_firewall, "[FIREWALL RULES COMPLETE]", challenge_template_id, user_id)

            reset_expiration_timer(challenge.id, db_conn, expiration_duration_minutes=60)

        except Exception as e:
            stop_challenge(user_id)
            raise ValueError(f"Error launching challenge: {e}")

        accessible_networks = [network.subnet for network in challenge.networks.values() if network.accessible]
        accessible_networks.sort()


        launch_timing_logger(start_time, "[LAUNCH COMPLETE]", challenge_template_id, user_id)

    finally:
        release_exclusive_launch_lock(user_id, launch_lock)

    return accessible_networks


def try_attach_to_running_warmup(challenge_template_id, user_id, db_conn):
    """
    Try to attach to a running warmup challenge for the given user ID and challenge template ID.
    """

    with db_conn.cursor() as cursor:
        cursor.execute("""
            WITH running_warmup AS (
                SELECT id
                FROM challenges
                WHERE challenge_template_id = %s
                AND lifecycle_state = 'PROVISIONING'
                AND pre_assigned_user_id IS NULL
                ORDER BY id
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE challenges
            SET pre_assigned_user_id = %s
            WHERE id IN (SELECT id FROM running_warmup)
            RETURNING id;
        """, (challenge_template_id, user_id))
        row = cursor.fetchone()

        if row is None:
            return None

    return row[0]


def check_running_warmup(challenge_template_id, user_id, db_conn):
    """
    Check if there is a running warmup challenge for the given user ID and challenge template ID.
    """

    with db_conn.cursor() as cursor:
        cursor.execute("""
            SELECT id
            FROM challenges
            WHERE challenge_template_id = %s
            AND lifecycle_state in ('PROVISIONING', 'READY')
            AND pre_assigned_user_id = %s
            LIMIT 1;
        """, (challenge_template_id, user_id))
        row = cursor.fetchone()

        if row is None:
            return None

    return row[0]


def acquire_exclusive_launch_lock(user_id):
    """
    Acquire an exclusive lock for launching a challenge for the given user ID.
    """

    lock_file_path = os.path.join(challenge_launch_lock_dir, f"user_{user_id}.lock")
    os.makedirs(challenge_launch_lock_dir, exist_ok=True)
    lock_file = open(lock_file_path, 'w')

    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except Exception as e:
        lock_file.close()
        raise RuntimeError(f"Failed to acquire launch lock for user {user_id}: {e}")

    return lock_file


def release_exclusive_launch_lock(user_id, launch_lock):
    """
    Release the exclusive lock for launching a challenge for the given user ID.
    """

    try:
        fcntl.flock(launch_lock, fcntl.LOCK_UN)
    finally:
        launch_lock.close()


def fetch_machines(challenge, db_conn):
    """
    Fetch machines for the given challenge.
    """

    with db_conn.cursor() as cursor:
        cursor.execute("""
            SELECT id, machine_template_id
            FROM machines
            WHERE challenge_id = %s
            """, (challenge.id,))

        for row in cursor.fetchall():
            machine_id = row[0]
            machine_template_id = row[1]

            machine_template = MachineTemplate(machine_template_id, challenge.template)
            machine = Machine(machine_id, machine_template, challenge)
            challenge.add_machine(machine)
            machine_template.set_child(machine)

def fetch_networks_and_connections(challenge, db_conn):
    """
    Fetch networks and connections for the given challenge.
    """

    with db_conn.cursor() as cursor:
        cursor.execute("""
            SELECT n.id, n.network_template_id, n.subnet, n.host_device, nt.accessible
            FROM networks n, network_templates nt
            WHERE n.challenge_id = %s
            AND n.network_template_id = nt.id
            """, (challenge.id,))

        for row in cursor.fetchall():
            network_id = row[0]
            network_template_id = row[1]
            subnet = row[2]
            host_device = row[3]
            accessible = row[4]

            network_template = NetworkTemplate(network_template_id, accessible)
            network = Network(network_id, network_template, subnet, host_device, accessible)
            challenge.add_network(network)

        cursor.execute("""
            SELECT machine_id, network_id, client_mac, client_ip
            FROM network_connections
            WHERE network_id IN (
                SELECT id FROM networks WHERE challenge_id = %s
            )
            """, (challenge.id,))

        for row in cursor.fetchall():
            machine_id = row[0]
            network_id = row[1]
            client_mac = row[2]
            client_ip = row[3]

            machine = challenge.machines[machine_id]
            network = challenge.networks[network_id]

            connection = Connection(machine, network, client_mac, client_ip)
            challenge.add_connection(connection)
            network.add_connection(connection)
            machine.add_connection(connection)


def get_ready_challenge(challenge_template, db_conn, user_id=None):
    """
    Get a ready challenge from the database.
    """

    with db_conn.cursor() as cursor:
        if user_id is None:
            cursor.execute("""
                WITH ready_challenges AS (
                    SELECT id, subnet
                    FROM challenges
                    WHERE challenge_template_id = %s
                    AND lifecycle_state = 'READY'
                    ORDER BY id
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE challenges
                SET lifecycle_state = 'ASSIGNED'
                WHERE id IN (SELECT id FROM ready_challenges)
                RETURNING id, subnet;
            """, (challenge_template.id,))
            row = cursor.fetchone()

            if row is None:
                return None

            challenge_id = row[0]
            subnet = row[1]

            challenge = Challenge(challenge_id=challenge_id, template=challenge_template, subnet=subnet)
            return challenge
        else:
            cursor.execute("""
                WITH ready_challenges AS (
                    SELECT id, subnet
                    FROM challenges
                    WHERE pre_assigned_user_id = %s
                    AND challenge_template_id = %s
                    AND lifecycle_state = 'READY'
                    ORDER BY id
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE challenges
                SET lifecycle_state = 'ASSIGNED'
                WHERE id IN (SELECT id FROM ready_challenges)
                RETURNING id, subnet;
            """, (user_id, challenge_template.id))
            row = cursor.fetchone()

            if row is None:
                return None

            challenge_id = row[0]
            subnet = row[1]

            challenge = Challenge(challenge_id=challenge_id, template=challenge_template, subnet=subnet)
            return challenge



def clone_machines(challenge_template, challenge, db_conn):
    """
    Clone machines from the given machine template IDs.
    """

    max_machine_id = 899_999_999

    for machine_template in challenge_template.machine_templates.values():
        with db_conn.cursor() as cursor:
            cursor.execute("""
            INSERT INTO machines (machine_template_id, challenge_id)
            VALUES (%s, %s)
            RETURNING id
            """, (machine_template.id, challenge.id))

            machine_id = cursor.fetchone()[0]

            if machine_id > max_machine_id:
                raise ValueError("Machine ID exceeds maximum limit")

            machine = Machine(machine_id=machine_id, template=machine_template, challenge=challenge)

            # Add machine template to challenge template
            challenge.add_machine(machine)
            machine_template.set_child(machine)

        clone_vm_api_call(machine_template, machine)



def vmid_to_ipv6(vmid, offset=0x1000):
    """
    Create ipv6 address from a VMID.
    """
    host_id = offset + vmid
    high = (host_id >> 16) & 0xFFFF
    low  = host_id & 0xFFFF
    return f"fd12:3456:789a:1::{high:x}:{low:x}"



def wait_for_qemu_guest_agent(machine, timeout=120):
    """
    Wait until QEMU Guest Agent is ready
    """
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            cmd = f"qm guest exec {machine.id} -- echo 'ready'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                launch_timing_logger(start_time, f"[GUEST AGENT RESPONDED]", machine.challenge.template.id, None, VM_ID=machine.id)
                return True
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass

        time.sleep(5)

    raise TimeoutError(f"QEMU Guest Agent timeout for VM {machine.id}")


def generate_user_specific_flag(flag_secret, user_unique_id):
    """
    Generate a user-specific flag using the secret and user unique id.
    Format: ITSEC{sha1.hmac_hash(key=secret,message=unique_id)}
    """
    hash_value = hmac.new(
        flag_secret.encode('utf-8'),
        user_unique_id.encode('utf-8'),
        hashlib.sha1
    ).hexdigest()
    return f"ITSEC{{{hash_value}}}"


def process_all_user_specific_flags(challenge, user_unique_id):
    """
    Process all user-specific flags for the challenge.
    Generates personalized flags and writes them to the appropriate VMs.
    """
    try:
        if not hasattr(challenge.template, 'flags'):
            print(f"[Info] No flags defined for challenge template {challenge.template.id}", flush=True)
            return

        flags_by_machine = {}
        for flag in challenge.template.flags:
            if flag['user_specific'] and flag['machine_template_id']:
                machine_template_id = flag['machine_template_id']

                print(f"[Info] Processing flag {flag} for machine template {machine_template_id}", flush=True)

                machine = None
                for m in challenge.machines.values():
                    if m.template.id == machine_template_id:
                        machine = m
                        break

                    if machine is None:
                        print(f"[Warning] Machine template {machine_template_id} not found in challenge", flush=True)
                        continue

                if machine.id not in flags_by_machine:
                    flags_by_machine[machine.id] = []

                print(f"[Info] Processing flag {flag} for machine {machine.id}", flush=True)

                user_flag = generate_user_specific_flag(flag['flag'], user_unique_id)
                print(f"[Info] Generated user-specific flag for {user_unique_id}: {user_flag}", flush=True)
                flag_path = f"/root/flag_{flag['order_index']}.txt"
                flags_by_machine[machine.id].append({
                    'flag': user_flag,
                    'path': flag_path,
                })


    except Exception as e:
        print(f"[Error] Failed to process flags for challenge {challenge.id}, user {user_email}: {e}", flush=True)
        raise e

    print(f"[Info] Finished generating user-specific flags for challenge {challenge.id} and user {user_email}", flush=True)

    try:
        flag_write_threads = []
        for machine_id, flags in flags_by_machine.items():
            flag_write_threads.append(threading.Thread(target=write_user_specific_flags_to_vm, args=(machine_id, flags)))

        print("[Info] Starting threads", flush=True)

        for thread in flag_write_threads:
            thread.start()

        for thread in flag_write_threads:
            thread.join()

    except Exception as e:
        print(f"[Error] Failed to write user-specific flags to VMs: {e}", flush=True)
        raise e


def write_user_specific_flags_to_vm(machine_id, flags):
    """
    Write user-specific flags to a VM via QEMU Guest Agent.
    """
    start_flag_write_time = time.time()

    flag_write_command = ""
    for flag in flags:
        escaped_flag = shlex.quote(flag['flag'])
        flag_path = flag['path']

        flag_write_command += f"echo {escaped_flag} > {flag_path} && chmod 600 {flag_path} && "

    print(f"[Info] Writing flags to VM {machine_id}: {flag_write_command}", flush=True)

    if flag_write_command != "":
        flag_write_command = flag_write_command.rstrip(" && ")
        result = subprocess.run(["qm", "guest", "exec", str(machine_id), "--",
                    "bash", "-c", flag_write_command], capture_output=True, text=True)

        if result.returncode != 0:
            raise RuntimeError(f"Failed to write flags to VM {machine_id}: {result.stderr}")

    launch_timing_logger(start_flag_write_time, f"[FLAG WRITE COMPLETE]", None, None, VM_ID=machine_id)

    print(f"[Info] Successfully wrote flags to VM {machine_id}", flush=True)


def generate_mac_address(machine_id, local_network_id, local_connection_id):
    """
    Generate a MAC address based on the machine ID, network ID, and connection ID.
    local_network_id, local_connection_id : 1-15 -> 2 nibbles combined
    machine_id : 100000000 -> 899999999 -> 8 nibbles -> hash to
    """
    machine_hex = hex(machine_id)[2:].zfill(8)[-8:]
    machine_bytes = [machine_hex[i:i + 2] for i in range(0, len(machine_hex), 2)]
    network_hex = hex(local_network_id)[2:]
    connection_hex = hex(local_connection_id)[2:]

    if len(machine_bytes) != 4:
        raise ValueError(f"Challenge ID must be 8 hex digits, got {len(machine_bytes) * 2} hex digits")

    if len(network_hex) > 1 or len(connection_hex) > 1:
        raise ValueError(f"Network ID and Connection ID must be 1 hex digit, got {len(network_hex)} and "
                         f"{len(connection_hex)} hex digits")

    mac = (f"02:{machine_bytes[0]}:{machine_bytes[1]}:{machine_bytes[2]}:{machine_bytes[3]}"
           f":{network_hex}{connection_hex}")
    return mac


def fetch_user_vpn_ip(user_id, db_conn):
    """
    Fetch the VPN IP address for the given user ID.
    """
    with db_conn.cursor() as cursor:
        cursor.execute("SELECT vpn_static_ip FROM users WHERE id = %s", (user_id,))
        user_vpn_ip = cursor.fetchone()[0]

    if user_vpn_ip is None:
        raise ValueError("User VPN IP not found")

    return user_vpn_ip


def fetch_user_unique_id(user_id, db_conn):
    """
    Fetch the email address for the given user ID.
    """
    with db_conn.cursor() as cursor:
        cursor.execute("SELECT unique_id FROM users WHERE id = %s", (user_id,))
        unique_id = cursor.fetchone()[0]

    if unique_id is None:
        raise ValueError("User email not found")

    return unique_id


def fetch_challenge_flags(challenge_template, db_conn):
    """
    Fetch challenge flags for the given challenge template.
    """
    with db_conn.cursor() as cursor:
        cursor.execute("""
           SELECT id, flag, description, points, order_index, user_specific, machine_template_id
           FROM challenge_flags
           WHERE challenge_template_id = %s
           ORDER BY order_index
       """, (challenge_template.id,))

        challenge_template.flags = []
        for row in cursor.fetchall():
            flag_data = {
                'id': row[0],
                'flag': row[1],
                'description': row[2],
                'points': row[3],
                'order_index': row[4],
                'user_specific': row[5],
                'machine_template_id': row[6]
            }
            challenge_template.flags.append(flag_data)


def add_iptables_rules(challenge, user_vpn_ip, vpn_monitoring_device, dmz_monitoring_device):
    """
    Update iptables rules for the given user VPN IP.
    """

    # Remove general user block from an earlier challenge stop
    subprocess.run(["iptables", "-D", "FORWARD", "-s", user_vpn_ip, "-d", CHALLENGES_ROOT_SUBNET_CIDR, "-j", "DROP"],
                     check=False, capture_output=True)
    subprocess.run(["iptables", "-D", "FORWARD", "-s", CHALLENGES_ROOT_SUBNET_CIDR, "-d", user_vpn_ip, "-j", "DROP"],
                     check=False, capture_output=True)

    for network in challenge.networks.values():
        # Allow intra-network traffic
        subprocess.run(
            ["iptables", "-A", "FORWARD", "-i", network.host_device, "-o", network.host_device, "-j", "ACCEPT"],
            check=True)

        # Allow DNS traffic to the router IP
        subprocess.run(
            ["iptables", "-A", "INPUT", "-i", network.host_device, "-d", network.router_ip, "-p", "udp", "--dport",
             "53", "-j", "ACCEPT"], check=True)
        subprocess.run(
            ["iptables", "-A", "INPUT", "-i", network.host_device, "-d", network.router_ip, "-p", "tcp", "--dport",
             "53", "-j", "ACCEPT"], check=True)

        # Disallow traffic to the router IP
        subprocess.run(["iptables", "-A", "INPUT", "-d", network.router_ip, "-j", "DROP"], check=True)

        # Set up qdisc
        subprocess.run(["tc", "qdisc", "add", "dev", network.host_device, "clsact"], check=False)

        # Mirror traffic on this network to monitoring_device
        subprocess.run([
            "tc", "filter", "add", "dev", network.host_device, "ingress", "protocol", "ip",
            "matchall",  # ADD THIS
            "action", "mirred", "egress", "mirror", "dev", vpn_monitoring_device
        ], check=True)

        subprocess.run([
            "tc", "filter", "add", "dev", network.host_device, "egress", "protocol", "ip",
            "matchall",  # ADD THIS
            "action", "mirred", "egress", "mirror", "dev", vpn_monitoring_device
        ], check=True)

        if network.accessible:
            for network_connection in network.connections.values():
                # Allow traffic from the user VPN IP to the client IP
                subprocess.run(
                    ["iptables", "-A", "FORWARD", "-i", "tun0", "-o", network.host_device, "-s", user_vpn_ip, "-d",
                     network_connection.client_ip, "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED", "-j",
                     "ACCEPT"], check=True)
                subprocess.run(
                    ["iptables", "-A", "FORWARD", "-i", network.host_device, "-o", "tun0", "-d", user_vpn_ip, "-s",
                     network_connection.client_ip, "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED", "-j",
                     "ACCEPT"], check=True)

        if network.is_dmz:
            # Allow traffic from the DMZ to the outside
            subprocess.run(
                ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "vmbr0", "-s", network.subnet, "!", "-d",
                 CHALLENGES_ROOT_SUBNET_CIDR, "-j", "MASQUERADE"], check=True)
            subprocess.run(
                ["iptables", "-A", "FORWARD", "-i", network.host_device, "-o", "vmbr0", "-s", network.subnet, "!",
                 "-d", CHALLENGES_ROOT_SUBNET_CIDR, "-m","conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED", "-j",
                 "ACCEPT"], check=True)
            subprocess.run(
                ["iptables", "-A", "FORWARD", "-i", "vmbr0", "-o", network.host_device, "-d", network.subnet, "!",
                 "-s", CHALLENGES_ROOT_SUBNET_CIDR, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j",
                 "ACCEPT"], check=True)

            # Set up qdisc for DMZ monitoring
            subprocess.run(["tc", "qdisc", "add", "dev", "vmbr0", "clsact"], check=False)

            # Mirror DMZ traffic (internet-bound only)
            subprocess.run([
                "tc", "filter", "add", "dev", network.host_device, "egress",
                "protocol", "ip", "flower",
                "src_ip", network.subnet,
                "action", "mirred", "egress", "mirror", "dev", dmz_monitoring_device
            ], check=True)
            subprocess.run([
                "tc", "filter", "add", "dev", "vmbr0", "ingress",
                "protocol", "ip", "flower",
                "dst_ip", network.subnet,
                "action", "mirred", "egress", "mirror", "dev", dmz_monitoring_device
            ], check=True)


def start_dnsmasq_instances(challenge, user_vpn_ip):
    """
    Start a dnsmasq process per network that needs DNS/DHCP, isolated by interface.
    Each instance will only answer for its configured domains and will ignore unknown zones,
    causing the client to move to the next nameserver on timeout rather than receiving NXDOMAIN.
    """

    machines_with_user_routes = {}

    for network in challenge.networks.values():
        config_path = os.path.join(DNSMASQ_INSTANCES_DIR, f"dnsmasq_{network.host_device}.conf")
        pidfile_path = os.path.join(DNSMASQ_INSTANCES_DIR, f"dnsmasq_{network.host_device}.pid")
        leases_path = os.path.join(DNSMASQ_INSTANCES_DIR, f"dnsmasq_{network.host_device}.leases")
        log_path = os.path.join(DNSMASQ_INSTANCES_DIR, f"dnsmasq_{network.host_device}.log")

        for connection in network.connections.values():
            if connection.machine.id not in machines_with_user_routes and network.accessible:
                machines_with_user_routes[connection.machine.id] = connection
                with open(config_path, "a") as f:
                    f.write(f"dhcp-option=tag:{connection.machine.id},option:classless-static-route,{user_vpn_ip}/32,"
                            f"{network.router_ip}\n")

        print(f"[Info] Starting dnsmasq for network {network.id} on device {network.host_device}", flush=True)
        print(f"[Info] Config path: {config_path}", flush=True)
        print(f"[Info] Leases path: {leases_path}", flush=True)
        print(f"[Info] Log path: {log_path}", flush=True)
        print(f"[Info] Pidfile path: {pidfile_path}", flush=True)

        # Launch the isolated dnsmasq instance
        subprocess.Popen([
            "dnsmasq",
            f"--conf-file={config_path}",
            f"--pid-file={pidfile_path}",
            f"--dhcp-leasefile={leases_path}",
            f"--log-facility={log_path}",
        ])

        print(f"[Info] Started dnsmasq for network {network.id} on device {network.host_device}", flush=True)


def add_running_challenge_to_user(challenge, user_id, db_conn):
    """
    Add the running challenge to the user.
    """

    with db_conn.cursor() as cursor:
        cursor.execute("UPDATE users SET running_challenge = %s WHERE id = %s", (challenge.id, user_id))


def reset_expiration_timer(challenge_id, db_conn, expiration_duration_minutes=60):
    """
    Reset the expiration timer for the challenge.
    """

    with db_conn.cursor() as cursor:
        cursor.execute("""
            UPDATE challenges
            SET expires_at = CURRENT_TIMESTAMP + INTERVAL '%s minutes'
            WHERE id = %s
        """, (expiration_duration_minutes, challenge_id))
