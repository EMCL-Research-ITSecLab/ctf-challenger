import random
import subprocess
import threading

from subnet_calculations import nth_network_subnet
from DatabaseClasses import *
from proxmox_api_calls import *
import os
import shlex
from teardown_challenge import remove_database_entries, stop_dnsmasq_instances,remove_challenge_from_wazuh
from tenacity import retry, stop_after_attempt, wait_exponential_jitter
import time
from dotenv import load_dotenv, find_dotenv
import hashlib
import hmac
from launch_timing_logger import launch_timing_logger
from get_db_connection import db_connection_context
from qemu_ga_wrapper import GuestAgent, GuestAgentError

load_dotenv(find_dotenv())

WAZUH_ENROLLMENT_PASSWORD = os.getenv("WAZUH_ENROLLMENT_PASSWORD")

DNSMASQ_INSTANCES_DIR = "/etc/dnsmasq-instances/"
os.makedirs(DNSMASQ_INSTANCES_DIR, exist_ok=True)


@retry(stop=stop_after_attempt(10), wait=wait_exponential_jitter(initial=1, max=5, exp_base=1.1, jitter=1),
       reraise=True)
def warmup_challenge(pre_assigned_user_id, challenge_template_id, vpn_monitoring_device, dmz_monitoring_device):
    """
    Launch a challenge by creating a user and network device.
    """

    with db_connection_context() as db_conn:
        start_time = time.time()

        try:
            start_time_db_fetch = time.time()
            challenge_template = ChallengeTemplate(challenge_template_id)
            fetch_machines(challenge_template, db_conn)
            fetch_network_and_connection_templates(challenge_template, db_conn)
            fetch_domain_templates(challenge_template, db_conn)

            launch_timing_logger(start_time_db_fetch, "[WARMUP DB FETCH COMPLETE]", challenge_template_id, pre_assigned_user_id)
        except Exception as e:
            raise ValueError(f"Error fetching from database: {e}")

        try:
            challenge = create_challenge(challenge_template, db_conn, pre_assigned_user_id)
        except Exception as e:
            raise ValueError(f"Error creating challenge: {e}")

        try:
            start_time_machine_clone = time.time()
            clone_machines(challenge_template, challenge, db_conn)
            launch_timing_logger(start_time_machine_clone, "[WARMUP MACHINE CLONE COMPLETE]", challenge_template_id, pre_assigned_user_id)

            # Network setup
            start_time_network = time.time()
            attach_vrtmon_network(challenge)
            create_networks_and_connections(challenge_template, challenge, db_conn)
            create_domains(challenge_template, challenge, db_conn)
            create_network_devices(challenge)
            wait_for_networks_to_be_up(challenge)

            attach_networks_to_vms(challenge)
            configure_dnsmasq_instances(challenge)
            launch_timing_logger(start_time_network, "[WARMUP NETWORK SETUP COMPLETE]", challenge_template_id, pre_assigned_user_id)

            start_time_vm_boot = time.time()
            launch_machines(challenge)
            launch_timing_logger(start_time_vm_boot, "[WARMUP VM BOOT COMPLETE]", challenge_template_id, pre_assigned_user_id)

            start_time_wazuh = time.time()
            configure_wazuh_for_challenge(challenge)
            launch_timing_logger(start_time_wazuh, "[WARMUP WAZUH CONFIG COMPLETE]", challenge_template_id, pre_assigned_user_id)

            set_challenge_ready(challenge, db_conn)

        except Exception as e:
            undo_launch_challenge(challenge, db_conn)
            raise ValueError(f"Error launching challenge: {e}")

        launch_timing_logger(start_time, "[WARMUP COMPLETE]", challenge_template_id, pre_assigned_user_id)

        return challenge


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


def create_challenge(challenge_template, db_conn, pre_assigned_user_id=None):
    """
    Create a challenge for the given user ID and challenge template.
    """

    with db_conn.cursor() as cursor:
        cursor.execute("""
        INSERT INTO challenges (challenge_template_id, lifecycle_state, pre_assigned_user_id)
        VALUES (%s, 'PROVISIONING', %s)
        RETURNING id, subnet
        """, (challenge_template.id, pre_assigned_user_id))

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
    Configure Wazuh for all machines in parallel.
    Creates one thread per machine, starts all simultaneously, then joins.
    """

    threads = []
    exceptions = []

    def worker(machine):
        try:
            configure_ipv6_and_wazuh_via_guest_agent(machine, manager_ip)
        except Exception as e:
            print(f"[Error] Failed to configure Wazuh for VM {machine.id}: {e}", flush=True)
            exceptions.append(e)

    # Create one thread per machine
    for machine in challenge.machines.values():
        thread = threading.Thread(target=worker, args=(machine,))
        threads.append(thread)

    # Start all threads simultaneously
    for thread in threads:
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # If any thread failed, raise the first exception
    if exceptions:
        raise exceptions[0]


def wait_for_qemu_guest_agent(machine, timeout=120):
    """
    Wait until QEMU Guest Agent is ready.
    """
    start_time = time.time()
    deadline = time.monotonic() + timeout
    socket_wait_timeout = max(10.0, timeout * 0.9)

    while time.monotonic() < deadline:
        try:
            with GuestAgent(vmid=machine.id, socket_wait_timeout=socket_wait_timeout) as ga:
                if ga.ping():
                    launch_timing_logger(start_time, f"[GUEST AGENT RESPONDED]", machine.challenge.template.id, None, VM_ID=machine.id)
                    return True
        except GuestAgentError:
            pass

        time.sleep(5)

    raise TimeoutError(f"QEMU Guest Agent timeout for VM {machine.id}")


def configure_ipv6_and_wazuh_via_guest_agent(machine, manager_ip="fd12:3456:789a:1::101"):
    """
    Configure IPv6 and Wazuh agent via QEMU Guest Agent
    All Wazuh-related commands are batched into a single execution.
    """
    ipv6 = vmid_to_ipv6(machine.id)
    vrtmon_gw = "fd12:3456:789a:1::1"
    agent_name = f"Agent_{machine.id}"

    full_start_time = time.time()

    # Single aggregated command using &&
    aggregated_cmd = f"""
    iface=$(ip -o link | awk "/0a:01/ {{print \\$2; exit}}" | tr -d :) && \
    ip -6 addr add {ipv6}/64 dev $iface && \
    ip -6 route add default via {vrtmon_gw} && \
    systemctl stop wazuh-agent 2>/dev/null || true && \
    /var/monitoring/wazuh-agent/setup_wazuh.sh \
        --register \
        --manager={manager_ip} \
        --name={agent_name} \
        --password={WAZUH_ENROLLMENT_PASSWORD} \
        --yes && \
    systemctl daemon-reload && \
    systemctl enable wazuh-agent && \
    systemctl start wazuh-agent && \
    rm -rf /var/monitoring
    """

    try:
        with GuestAgent(vmid=machine.id) as ga:
            result = ga.exec(aggregated_cmd, timeout=120)
    except GuestAgentError as e:
        raise RuntimeError(f"Guest agent error while configuring Wazuh for VM {machine.id}: {e}") from e

    if not result:
        raise RuntimeError(
            f"Failed to configure Wazuh for VM {machine.id}: {result.stderr}"
        )

    launch_timing_logger(
        full_start_time,
        "[WAZUH FULL CONFIG COMPLETE]",
        machine.challenge.template.id,
        None,
        VM_ID=machine.id
    )


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


def create_networks_and_connections(challenge_template, challenge, db_conn):
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

        challenge_id_hex = f"{challenge.id:06x}"
        local_network_id_hex = f"{local_network_id:01x}"

        network_host_device = f"vrt{challenge_id_hex}{local_network_id_hex}"

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



def configure_dnsmasq_instances(challenge):
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
                f.write(f"dhcp-option=tag:{tag},option:dns-server,{upstream},1.1.1.1,1.0.0.1\n")

                if network.is_dmz:
                    if connection.machine.id not in machines_with_internet_access:
                        machines_with_internet_access[connection.machine.id] = connection
                        f.write(f"dhcp-option=tag:{tag},option:classless-static-route,0.0.0.0/0,{network.router_ip}\n")

                # Add only authoritative server for each domain
                for domain in connection.machine.domains:
                    f.write(f"address=/{domain}/{connection.client_ip}\n")


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

    # Wait for all VMs to boot and qemu-ga to be ready
    for machine in challenge.machines.values():
        wait_for_qemu_guest_agent(machine)


def set_challenge_ready(challenge, db_conn):
    """
    Set the challenge lifecycle state to READY.
    """

    with db_conn.cursor() as cursor:
        cursor.execute("""
        UPDATE challenges
        SET lifecycle_state = 'READY'
        WHERE id = %s
        """, (challenge.id,))


def undo_launch_challenge(challenge, db_conn):
    """
    Undo the launch of a challenge by stopping and deleting the machines and networks.
    """

    if challenge is None:
        return

    stop_and_delete_machines(challenge)
    delete_network_devices(challenge)
    stop_dnsmasq_instances(challenge)
    remove_database_entries(challenge, db_conn)
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