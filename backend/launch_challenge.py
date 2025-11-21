import random
import subprocess

from subnet_calculations import nth_network_subnet
from DatabaseClasses import *
from proxmox_api_calls import *
import os
import shlex
from stop_challenge import delete_iptables_rules, remove_database_entries, stop_dnsmasq_instances,remove_challenge_from_wazuh
from tenacity import retry, stop_after_attempt, wait_exponential_jitter
import time
from dotenv import load_dotenv, find_dotenv
import hashlib
import hmac

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


@retry(stop=stop_after_attempt(10), wait=wait_exponential_jitter(initial=1, max=5, exp_base=1.1, jitter=1),
       reraise=True)
def launch_challenge(challenge_template_id, user_id, db_conn, vpn_monitoring_device, dmz_monitoring_device):
    """
    Launch a challenge by creating a user and network device.
    """

    launch_lock = acquire_exclusive_launch_lock(user_id)

    try:
        with db_conn:
            try:
                user_vpn_ip = fetch_user_vpn_ip(user_id, db_conn)
                user_email = fetch_user_email(user_id, db_conn)
                challenge_template = ChallengeTemplate(challenge_template_id)
                fetch_machines(challenge_template, db_conn)
                fetch_network_and_connection_templates(challenge_template, db_conn)
                fetch_domain_templates(challenge_template, db_conn)
                fetch_challenge_flags(challenge_template, db_conn)
            except Exception as e:
                raise ValueError(f"Error fetching from database: {e}")

            try:
                challenge = create_challenge(challenge_template, db_conn)
            except Exception as e:
                raise ValueError(f"Error creating challenge: {e}")

            try:
                clone_machines(challenge_template, challenge, db_conn)
                attach_vrtmon_network(challenge)
                create_networks_and_connections(challenge_template, challenge, user_id, db_conn)
                create_domains(challenge_template, challenge, db_conn)
                create_network_devices(challenge)
                wait_for_networks_to_be_up(challenge)

                # Attach final networks and start VMs
                attach_networks_to_vms(challenge)
                start_dnsmasq_instances(challenge, user_vpn_ip)
                launch_machines(challenge)

                configure_wazuh_for_challenge(challenge)

                process_all_user_specific_flags(challenge, user_email)

                add_running_challenge_to_user(challenge, user_id, db_conn)
                add_iptables_rules(challenge, user_vpn_ip, vpn_monitoring_device, dmz_monitoring_device)

            except Exception as e:
                undo_launch_challenge(challenge, user_id, user_vpn_ip, db_conn)
                raise ValueError(f"Error launching challenge: {e}")

            accessible_networks = [network.subnet for network in challenge.networks.values() if network.accessible]
            accessible_networks.sort()
    except Exception as e:
        raise e
    finally:
        release_exclusive_launch_lock(user_id, launch_lock)

    return accessible_networks


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


def fetch_machines(challenge_template, db_conn):
    """
    Fetch machine templates for the given challenge.
    """

    with db_conn.cursor() as cursor:
        cursor.execute("SELECT id FROM machine_templates WHERE challenge_template_id = %s", (challenge_template.id,))

        for row in cursor.fetchall():
            machine_template = MachineTemplate(machine_template_id=row[0], challenge_template=challenge_template)

            # Add machine template to challenge template
            challenge_template.add_machine_template(machine_template)


def fetch_network_and_connection_templates(challenge_template, db_conn):
    """
    Fetch network and connection templates for the given machine templates.
    """

    for machine_template in challenge_template.machine_templates.values():
        with db_conn.cursor() as cursor:
            cursor.execute("""
            SELECT nt.id, nt.accessible, nt.is_dmz
            FROM network_templates nt, network_connection_templates ct
            WHERE ct.machine_template_id = %s
            AND ct.network_template_id = nt.id
            """, (machine_template.id,))

            for row in cursor.fetchall():
                network_id = row[0]

                if challenge_template.network_templates.get(network_id) is None:
                    network_template = NetworkTemplate(network_template_id=network_id, accessible=row[1])
                    network_template.set_is_dmz(row[2])
                    challenge_template.add_network_template(network_template)
                else:
                    network_template = challenge_template.network_templates[network_id]

                connection_template = ConnectionTemplate(
                    machine_template=machine_template,
                    network_template=network_template
                )

                challenge_template.add_connection_template(connection_template)
                network_template.add_connected_machine(machine_template)
                machine_template.add_connected_network(network_template)


def fetch_domain_templates(challenge_template, db_conn):
    """
    Fetch domain templates for the given machine templates and network templates.
    """

    for machine_template in challenge_template.machine_templates.values():
        with db_conn.cursor() as cursor:
            cursor.execute("""
            SELECT dt.domain_name
            FROM domain_templates dt
            WHERE dt.machine_template_id = %s
            """, (machine_template.id,))

            for row in cursor.fetchall():
                domain_template = DomainTemplate(machine_template=machine_template, domain=row[0])

                challenge_template.add_domain_template(domain_template)
                machine_template.add_domain_template(domain_template)


def create_challenge(challenge_template, db_conn):
    """
    Create a challenge for the given user ID and challenge template.
    """

    with db_conn.cursor() as cursor:
        cursor.execute("""
        INSERT INTO challenges (challenge_template_id)
        VALUES (%s)
        RETURNING id, subnet
        """, (challenge_template.id,))

        challenge_id, challenge_subnet_value = cursor.fetchone()
        challenge_subnet = ChallengeSubnet(challenge_subnet_value)
        challenge = Challenge(challenge_id=challenge_id, template=challenge_template, subnet=challenge_subnet.subnet)

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


def attach_vrtmon_network(challenge):
    """
    Attach the vrtmon management network (net31) to all VMs.
    This network is used for monitoring and Wazuh communication.
    """
    for machine in challenge.machines.values():
        add_network_device_api_call(
            machine.id,
            nic="net31",
            bridge="vrtmon",
            model="e1000",
            mac_index="0A:01"
        )


def vmid_to_ipv6(vmid, offset=0x1000):
    """
    Create ipv6 address from a VMID.
    """
    host_id = offset + vmid
    high = (host_id >> 16) & 0xFFFF
    low  = host_id & 0xFFFF
    return f"fd12:3456:789a:1::{high:x}:{low:x}"


def configure_wazuh_for_challenge(challenge, manager_ip="fd12:3456:789a:1::101"):
    """
    Configure Wazuh for all machines in a challenge via QEMU Guest Agent
    """
    # Wait for all VMs to boot and qemu-ga to be ready
    for machine in challenge.machines.values():
        wait_for_qemu_guest_agent(machine)

    # Configure Wazuh on all machines
    for machine in challenge.machines.values():
        try:
            configure_ipv6_and_wazuh_via_guest_agent(machine, manager_ip)
        except Exception as e:
            print(f"[Error] Failed to configure Wazuh for VM {machine.id}: {e}", flush=True)
            raise


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
                return True
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass

        time.sleep(5)

    raise TimeoutError(f"QEMU Guest Agent timeout for VM {machine.id}")


def configure_ipv6_and_wazuh_via_guest_agent(machine, manager_ip="fd12:3456:789a:1::101"):
    """
    Configure IPv6 on vrtmon interface and Wazuh agent via QEMU Guest Agent
    """
    ipv6 = vmid_to_ipv6(machine.id)
    vrtmon_gw = "fd12:3456:789a:1::1"
    agent_name = f"Agent_{machine.id}"

    # Step 1: Configure IPv6
    cmd = f"""iface=$(ip -o link | awk "/0a:01/ {{print \\$2; exit}}" | tr -d :) && \
    ip -6 addr add {ipv6}/64 dev $iface && \
    ip -6 route add default via {vrtmon_gw}"""

    subprocess.run(f"qm guest exec {machine.id} -- bash -c '{cmd}'", shell=True, capture_output=True, text=True)

    # Step 2: Stop Wazuh agent if running
    cmd = ["qm", "guest", "exec", str(machine.id), "--", "systemctl", "stop", "wazuh-agent"]
    subprocess.run(cmd, capture_output=True, text=True, timeout=30)  # Ignore errors

    # Step 3: Register agent with manager
    cmd = [
        "qm", "guest", "exec", str(machine.id), "--",
        "/var/monitoring/wazuh-agent/setup_wazuh.sh",
        "--register",
        f"--manager={manager_ip}",
        f"--name={agent_name}",
        f"--password={WAZUH_ENROLLMENT_PASSWORD}",
        "--yes"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

    if result.returncode != 0:
        raise RuntimeError(f"Failed to register Wazuh agent for VM {machine.id}: {result.stderr}")

    # Step 4: Start Wazuh agent
    cmd = ["qm", "guest", "exec", str(machine.id), "--", "systemctl", "daemon-reload"]
    subprocess.run(cmd, capture_output=True, text=True, timeout=30)

    cmd = ["qm", "guest", "exec", str(machine.id), "--", "systemctl", "enable", "wazuh-agent"]
    subprocess.run(cmd, capture_output=True, text=True, timeout=30)

    cmd = ["qm", "guest", "exec", str(machine.id), "--", "systemctl", "start", "wazuh-agent"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

    if result.returncode != 0:
        raise RuntimeError(f"Failed to start Wazuh agent for VM {machine.id}: {result.stderr}")

    # Step 5: Clean up monitoring directory
    cmd = ["qm", "guest", "exec", str(machine.id), "--", "rm", "-rf", "/var/monitoring"]
    subprocess.run(cmd, capture_output=True, text=True, timeout=30)


def generate_user_specific_flag(flag_secret, user_email):
    """
    Generate a user-specific flag using the secret and user email.
    Format: ITSEC{sha1.hmac_hash(key=secret,message=email)}
    """
    hash_value = hmac.new(
        flag_secret.encode('utf-8'),
        user_email.encode('utf-8'),
        hashlib.sha1
    ).hexdigest()
    return f"ITSEC{{{hash_value}}}"


def process_all_user_specific_flags(challenge, user_email):
    """
    Process all user-specific flags for the challenge.
    Generates personalized flags and writes them to the appropriate VMs.
    """
    if not hasattr(challenge.template, 'flags'):
        return

    flags_by_machine = {}
    for flag in challenge.template.flags:
        if flag['user_specific'] and flag['machine_template_id']:
            machine_template_id = flag['machine_template_id']
            if machine_template_id not in flags_by_machine:
                flags_by_machine[machine_template_id] = []
            flags_by_machine[machine_template_id].append(flag)

    for machine_template_id, flags in flags_by_machine.items():
        machine = None
        for m in challenge.machines.values():
            if m.template.id == machine_template_id:
                machine = m
                break

        if machine is None:
            print(f"[Warning] Machine template {machine_template_id} not found in challenge", flush=True)
            continue

        try:
            write_user_specific_flags_to_vm(machine, flags, user_email)
        except Exception as e:
            print(f"[Error] Failed to write flags to VM {machine.id}: {e}", flush=True)
            raise


def write_user_specific_flags_to_vm(machine, flags, user_email):
    """
    Write user-specific flags to a VM via QEMU Guest Agent.
    """
    for flag in flags:
        order_index = flag['order_index']
        flag_secret = flag['flag']

        personalized_flag = generate_user_specific_flag(flag_secret, user_email)

        flag_path = f"/root/flag_{order_index}.txt"

        escaped_flag = shlex.quote(personalized_flag)

        cmd = ["qm", "guest", "exec", str(machine.id), "--",
               "bash", "-c", f"echo {escaped_flag} > {flag_path} && chmod 600 {flag_path}"]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode != 0:
            raise RuntimeError(f"Failed to write flag {order_index} to VM {machine.id}: {result.stderr}")

        print(f"[Info] Written flag_{order_index}.txt to VM {machine.id}", flush=True)


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


def create_networks_and_connections(challenge_template, challenge, user_id, db_conn):
    """
    Create networks and connections for the given challenge.
    """

    possible_network_subnets = []

    for i in range(2**4):
        possible_network_subnets.append(nth_network_subnet(challenge.subnet_ip, i))

    network_subnets = random.sample(possible_network_subnets, len(challenge_template.network_templates))

    local_network_id = 0
    for network_template, network_subnet in zip(challenge_template.network_templates.values(), network_subnets):
        local_network_id += 1
        available_client_ips = {nth_machine_ip(network_subnet[:-3], i) for i in range(2, 15)}

        user_id_hex = f"{user_id:06x}"
        local_network_id_hex = f"{local_network_id:01x}"

        network_host_device = f"vrt{user_id_hex}{local_network_id_hex}"

        if len(network_host_device) != 10:
            raise ValueError(f"Network host device must be 10 hex digits, got {len(network_host_device)} hex digits "
                             f"({network_host_device})")

        with db_conn.cursor() as cursor:
            cursor.execute("""
            INSERT INTO networks (network_template_id, subnet, host_device, challenge_id)
            VALUES (%s, %s, %s, %s)
            RETURNING id""", (network_template.id, network_subnet, network_host_device, challenge.id))

            network_id = cursor.fetchone()[0]
            network = Network(
                network_id=network_id,
                template=network_template,
                subnet=network_subnet,
                host_device=network_host_device,
                accessible=network_template.accessible
            )
            network.set_is_dmz(network_template.is_dmz)
            challenge.add_network(network)

        for local_connection_id, machine_template in enumerate(network_template.connected_machines.values()):
            machine = machine_template.child

            client_mac = generate_mac_address(machine.id, local_network_id, local_connection_id)
            client_ip = random.choice(list(available_client_ips))
            available_client_ips.remove(client_ip)

            if machine is None:
                raise ValueError("Machine ID not found")

            with db_conn.cursor() as cursor:
                cursor.execute("""
                INSERT INTO network_connections (machine_id, network_id, client_mac, client_ip)
                VALUES (%s, %s, %s, %s)
                """, (machine.id, network.id, client_mac, client_ip))

                connection = Connection(machine=machine, network=network, client_mac=client_mac, client_ip=client_ip)
                challenge.add_connection(connection)
                network.add_connection(connection)
                machine.add_connection(connection)


def create_domains(challenge_template, challenge, db_conn):
    """
    Create domains for the given challenge.
    """

    for domain_template in challenge_template.domain_templates.values():
        machine = domain_template.machine_template.child

        with db_conn.cursor() as cursor:
            cursor.execute("""
            INSERT INTO domains (machine_id, domain_name)
            VALUES (%s, %s)
            """, (machine.id, domain_template.domain))

            domain = Domain(machine=machine, domain=domain_template.domain)
            challenge.add_domain(domain)

            machine.add_domain(domain)


def create_network_devices(challenge):
    """
    Configure network devices for the given challenge and user ID.
    """

    for network in challenge.networks.values():
        create_network_api_call(network)

    reload_network_api_call()


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


def fetch_user_email(user_id, db_conn):
    """
    Fetch the email address for the given user ID.
    """
    with db_conn.cursor() as cursor:
        cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
        user_email = cursor.fetchone()[0]

    if user_email is None:
        raise ValueError("User email not found")

    return user_email


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


def wait_for_networks_to_be_up(challenge, try_timeout=3, max_tries=10):
    """
    Wait for networks to be up.
    """

    host_devices = [network.host_device for network in challenge.networks.values()]
    all_devices_up = False

    tries = 0

    while not all_devices_up and tries < max_tries:
        tries += 1
        try_start = time.time()

        while time.time() - try_start < try_timeout and not all_devices_up:
            all_devices_up = True
            for device in host_devices:
                if not os.path.exists(f"/sys/class/net/{device}"):
                    all_devices_up = False

        if not all_devices_up:
            reload_network_api_call()

    if not all_devices_up:
        raise TimeoutError("Timed out waiting for networks to be up")



def start_dnsmasq_instances(challenge, user_vpn_ip):
    """
    Start a dnsmasq process per network that needs DNS/DHCP, isolated by interface.
    Each instance will only answer for its configured domains and will ignore unknown zones,
    causing the client to move to the next nameserver on timeout rather than receiving NXDOMAIN.
    """

    machines_with_user_routes = {}
    machines_with_internet_access = {}

    # Collect upstream DNS servers per machine
    dns_servers_by_machine = {machine_id: [] for machine_id in challenge.machines.keys()}
    for machine in challenge.machines.values():
        for connection in machine.connections.values():
            dns_servers_by_machine[machine.id].append(connection.network.router_ip)

    for network in challenge.networks.values():
        config_path = os.path.join(DNSMASQ_INSTANCES_DIR, f"dnsmasq_{network.host_device}.conf")
        pidfile_path = os.path.join(DNSMASQ_INSTANCES_DIR, f"dnsmasq_{network.host_device}.pid")
        leases_path = os.path.join(DNSMASQ_INSTANCES_DIR, f"dnsmasq_{network.host_device}.leases")
        log_path = os.path.join(DNSMASQ_INSTANCES_DIR, f"dnsmasq_{network.host_device}.log")

        with open(config_path, "w") as f:
            # Interface binding
            f.write(f"interface={network.host_device}\n")
            f.write("bind-interfaces\n")
            f.write("except-interface=lo\n")

            # DHCP range and router option
            f.write(f"dhcp-range={network.available_start_ip},{network.available_end_ip},24h\n")
            f.write(f"dhcp-option=option:router,{network.router_ip}\n")

            # Ensure dnsmasq only answers known domains and ignores unknown
            f.write("no-resolv\n")          # ignore /etc/resolv.conf
            f.write("no-poll\n")            # don't poll resolv.conf

            # For each connected machine, set DHCP and DNS behavior
            for connection in network.connections.values():
                tag = f"{connection.machine.id}"

                # DHCP host mapping and per-machine DNS
                f.write(f"dhcp-host={connection.client_mac},{connection.client_ip},set:{tag}\n")
                upstream = ",".join(dns_servers_by_machine[connection.machine.id])

                # Fallback to public DNS only if desired
                f.write(f"dhcp-option=tag:{tag},option:dns-server,{upstream},8.8.8.8,8.8.4.4\n")

                # Static route for first eligible machine
                if connection.machine.id not in machines_with_user_routes and network.accessible:
                    machines_with_user_routes[connection.machine.id] = connection
                    f.write(f"dhcp-option=tag:{tag},option:classless-static-route,{user_vpn_ip}/32,"
                            f"{network.router_ip}\n")

                if network.is_dmz:
                    if connection.machine.id not in machines_with_internet_access:
                        machines_with_internet_access[connection.machine.id] = connection
                        f.write(f"dhcp-option=tag:{tag},option:classless-static-route,0.0.0.0/0,{network.router_ip}\n")

                # Add only authoritative server for each domain
                for domain in connection.machine.domains:
                    f.write(f"address=/{domain}/{connection.client_ip}\n")

        # Launch the isolated dnsmasq instance
        subprocess.Popen([
            "dnsmasq",
            f"--conf-file={config_path}",
            f"--pid-file={pidfile_path}",
            f"--dhcp-leasefile={leases_path}",
            f"--log-facility={log_path}",
        ])


def attach_networks_to_vms(challenge):
    """
    Attach networks to virtual machines.
    """

    for machine in challenge.machines.values():
        attach_networks_to_vm_api_call(machine)


def launch_machines(challenge):
    """
    Launch machines.
    """

    for machine in challenge.machines.values():
        launch_vm_api_call(machine)


def add_running_challenge_to_user(challenge, user_id, db_conn):
    """
    Add the running challenge to the user.
    """

    with db_conn.cursor() as cursor:
        cursor.execute("UPDATE users SET running_challenge = %s WHERE id = %s", (challenge.id, user_id))


def undo_launch_challenge(challenge, user_id, user_vpn_ip, db_conn):
    """
    Undo the launch of a challenge by stopping and deleting the machines and networks.
    """

    if challenge is None:
        return

    stop_and_delete_machines(challenge)
    delete_network_devices(challenge)
    delete_iptables_rules(challenge, user_vpn_ip)
    stop_dnsmasq_instances(challenge)
    remove_database_entries(challenge, user_id, db_conn)
    remove_challenge_from_wazuh(challenge)


def stop_and_delete_machines(challenge):
    """
    Stop and delete the machines for a challenge.
    """

    for machine in challenge.machines.values():
        try:
            out = subprocess.run(["qm", "stop", str(machine.id), "--skiplock"], check=True, capture_output=True)
        except Exception as e:
            print(f"[Warning] Failed to stop VM {machine.id}: {e}", flush=True)
            try:
                print(out.stdout.decode(), flush=True)
                print(out.stderr.decode(), flush=True)
            except Exception:
                pass

        try:
            out = subprocess.run(["qm", "destroy", str(machine.id), "--skiplock"], check=True, capture_output=True)
        except Exception as e:
            print(f"[Warning] Failed to destroy VM {machine.id}: {e}", flush=True)
            try:
                print(out.stdout.decode(), flush=True)
                print(out.stderr.decode(), flush=True)
            except Exception:
                pass


def delete_network_devices(challenge):
    """
    Delete network devices for the given challenge.
    """

    for network in challenge.networks.values():
        try:
            delete_network_api_call(network)
        except Exception:
            pass