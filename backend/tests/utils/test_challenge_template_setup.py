import os
import sys
import subprocess

BACKEND_DIR = "/root/ctf-challenger/backend"
sys.path.append(BACKEND_DIR)
from import_machine_templates import import_machine_templates
from delete_machine_templates import delete_machine_templates
from test_user_setup import test_user_setup
from DatabaseClasses import ChallengeTemplate, MachineTemplate, NetworkTemplate, DomainTemplate, ConnectionTemplate

OVA_FILES_DIR = "ova_files"
if not os.path.exists(OVA_FILES_DIR):
    os.makedirs(OVA_FILES_DIR)


def test_plain_ubuntu_setup(db_conn, creator_id=None):
    """
    Setup the a plain Ubuntu machine as challenge for testing purposes.
    """

    UBUNTU_BASE_SERVER_OVA_DIR = "/root/ctf-challenger/setup/ubuntu-base-server/"


    if not os.path.exists(UBUNTU_BASE_SERVER_OVA_DIR):
        raise FileNotFoundError(f"Directory {UBUNTU_BASE_SERVER_OVA_DIR} does not exist. Please run the setup script first.")

    dir_content = os.listdir(UBUNTU_BASE_SERVER_OVA_DIR)
    ova_file = next((f for f in dir_content if f.endswith(".ova")), None)

    if not ova_file:
        raise FileNotFoundError(f"No .ova file found in {UBUNTU_BASE_SERVER_OVA_DIR}. Please run the setup script first.")

    ubuntu_base_server_ova_path = os.path.join(UBUNTU_BASE_SERVER_OVA_DIR, ova_file)
    subprocess.run(["cp", ubuntu_base_server_ova_path, OVA_FILES_DIR], check=True)
    ubuntu_base_server_ova_path = os.path.join(OVA_FILES_DIR, ova_file)

    if not creator_id:
        creator_id = test_user_setup(db_conn, "testuser", "testpassword")

    challenge_template = {
        "name": "TEST: Plain Ubuntu Setup",
        "category": "misc",
        "difficulty": "easy",
        "is_active": True,
        "creator_id": creator_id,
    }
    with db_conn.cursor() as cursor:
        cursor.execute("INSERT INTO challenge_templates (name, category, difficulty, is_active, creator_id) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                       (challenge_template["name"], challenge_template["category"], challenge_template["difficulty"], challenge_template["is_active"], challenge_template["creator_id"]))
        challenge_template_id = cursor.fetchone()[0]
        challenge_template["id"] = challenge_template_id
    challenge_template_object = ChallengeTemplate(challenge_template["id"])

    machine_template = {
        "challenge_template_id": challenge_template["id"],
        "name": "Plain Ubuntu Machine",
        "disk_file_path": ubuntu_base_server_ova_path,
        "cores": 1,
        "ram_gb": 2
    }
    with db_conn.cursor() as cursor:
        cursor.execute("INSERT INTO machine_templates (challenge_template_id, name, disk_file_path, cores, ram_gb) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                       (machine_template["challenge_template_id"], machine_template["name"], machine_template["disk_file_path"], machine_template["cores"], machine_template["ram_gb"]))
        machine_template_id = cursor.fetchone()[0]
        machine_template["id"] = machine_template_id
    machine_template_object = MachineTemplate(machine_template["id"], challenge_template_object)
    machine_template_object.set_cores(machine_template["cores"])
    machine_template_object.set_ram(machine_template["ram_gb"] * 1024)  # Convert GB to MB
    machine_template_object.set_disk_file_path(machine_template["disk_file_path"])
    challenge_template_object.add_machine_template(machine_template_object)

    network_template = {
        "name": "Plain Ubuntu Network",
        "accessible": True,
        "is_dmz": True
    }
    with db_conn.cursor() as cursor:
        cursor.execute("INSERT INTO network_templates (name, accessible, is_dmz) VALUES (%s, %s, %s) RETURNING id",
                       (network_template["name"], network_template["accessible"], network_template["is_dmz"]))
        network_template_id = cursor.fetchone()[0]
        network_template["id"] = network_template_id
    network_template_object = NetworkTemplate(network_template["id"], network_template["accessible"])
    network_template_object.set_is_dmz(network_template["is_dmz"])
    challenge_template_object.add_network_template(network_template_object)
    machine_template_object.add_connected_network(network_template_object)
    network_template_object.add_connected_machine(machine_template_object)

    domain_template = {
        "machine_template_id": machine_template["id"],
        "domain_name": "testdomain.test",
    }
    with db_conn.cursor() as cursor:
        cursor.execute("INSERT INTO domain_templates (machine_template_id, domain_name) VALUES (%s, %s)",
                       (domain_template["machine_template_id"], domain_template["domain_name"]))
    domain_template_object = DomainTemplate(machine_template_object, domain_template["domain_name"])
    challenge_template_object.add_domain_template(domain_template_object)
    machine_template_object.add_domain_template(domain_template_object)

    network_connection_template = {
        "network_template_id": network_template["id"],
        "machine_template_id": machine_template["id"]
    }
    with db_conn.cursor() as cursor:
        cursor.execute("INSERT INTO network_connection_templates (network_template_id, machine_template_id) VALUES (%s, %s)",
                       (network_connection_template["network_template_id"], network_connection_template["machine_template_id"]))
    connection_template_object = ConnectionTemplate(machine_template_object, network_template_object)
    challenge_template_object.add_connection_template(connection_template_object)

    db_conn.commit()

    return creator_id, challenge_template_object
