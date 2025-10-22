import requests
from dotenv import load_dotenv
import os
from proxmoxer import ProxmoxAPI
import subprocess
import datetime
import sys

load_dotenv()

BACKEND_DIR = "/root/ctf-challenger/backend"
sys.path.append(BACKEND_DIR)

PROXMOX_HOST = os.getenv("PROXMOX_HOST", "10.0.0.1")
PROXMOX_USER = os.getenv("PROXMOX_USER", "root@pam")
PROXMOX_PASSWORD = os.getenv("PROXMOX_PASSWORD")
PROXMOX_PORT = os.getenv("PROXMOX_PORT", "8006")
BACKEND_PORT = os.getenv("BACKEND_PORT", "8000")
PROXMOX_INTERNAL_IP = os.getenv("PROXMOX_INTERNAL_IP", "10.0.3.4")
PROXMOX_EXTERNAL_IP = os.getenv("PROXMOX_EXTERNAL_IP", "10.0.3.4")
PROXMOX_HOSTNAME = os.getenv("PROXMOX_HOSTNAME", "pve")

UBUNTU_BASE_SERVER_URL = os.getenv("UBUNTU_BASE_SERVER_URL")

DATABASE_FILES_DIR = os.getenv("DATABASE_FILES_DIR", "/root/ctf-challenger/database")
DATABASE_NAME = os.getenv("DATABASE_NAME", "ctf_challenger")
DATABASE_USER = os.getenv("DATABASE_USER", "postgres")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
DATABASE_PORT = os.getenv("DATABASE_PORT", "5432")
DATABASE_HOST = os.getenv("DATABASE_HOST", "10.0.0.102")

WEBSERVER_FILES_DIR = os.getenv("WEBSERVER_FILES_DIR", "/root/ctf-challenger/webserver")
WEBSERVER_USER = os.getenv("WEBSERVER_USER", "www-data")
WEBSERVER_GROUP = os.getenv("WEBSERVER_GROUP", "www-data")
WEBSERVER_ROOT = os.getenv("WEBSERVER_ROOT", "/var/www/html")
WEBSERVER_HOST = os.getenv("WEBSERVER_HOST", "10.0.0.101")
WEBSERVER_HTTP_PORT = os.getenv("WEBSERVER_HTTP_PORT", "80")
WEBSERVER_HTTPS_PORT = os.getenv("WEBSERVER_HTTPS_PORT", "443")

BACKEND_FILES_DIR = os.getenv("BACKEND_FILES_DIR", "/root/ctf-challenger/backend")

OPENVPN_SUBNET = os.getenv("OPENVPN_SUBNET", "10.64.0.0/10")
OPENVPN_SERVER_IP = os.getenv("OPENVPN_SERVER_IP", "10.64.0.1")

BACKEND_NETWORK_SUBNET = os.getenv("BACKEND_NETWORK_SUBNET", "10.0.0.1/24")
BACKEND_NETWORK_ROUTER = os.getenv("BACKEND_NETWORK_ROUTER", "10.0.0.1")
BACKEND_NETWORK_DEVICE = os.getenv("BACKEND_NETWORK_DEVICE", "vrt-backend")
BACKEND_NETWORK_HOST_MIN = os.getenv("BACKEND_NETWORK_HOST_MIN", "10.0.0.2")
BACKEND_NETWORK_HOST_MAX = os.getenv("BACKEND_NETWORK_HOST_MAX", "10.0.0.254")

DATABASE_MAC_ADDRESS = os.getenv("DATABASE_MAC_ADDRESS", "0E:00:00:00:00:01")
WEBSERVER_MAC_ADDRESS = os.getenv("WEBSERVER_MAC_ADDRESS", "0E:00:00:00:00:02")

WEBSITE_ADMIN_USER = os.getenv("WEBSITE_ADMIN_USER", "admin")
WEBSITE_ADMIN_PASSWORD = os.getenv("WEBSITE_ADMIN_PASSWORD")

SYSTEMD_PATH = "/etc/systemd/system"
DNSMASQ_SERVICE_PATH = os.path.join(SYSTEMD_PATH, "dnsmasq-backend.service")
IPTABLES_SERVICE_PATH = os.path.join(SYSTEMD_PATH, "iptables-backend.service")

BACKEND_CERTIFICATE_DIR = os.path.join(BACKEND_FILES_DIR, "certificates")
BACKEND_CERTIFICATE_FILE = os.path.join(BACKEND_CERTIFICATE_DIR, "backend.crt")
BACKEND_CERTIFICATE_KEY_FILE = os.path.join(BACKEND_CERTIFICATE_DIR, "backend.key")

BACKEND_AUTHENTICATION_TOKEN = os.getenv("BACKEND_AUTHENTICATION_TOKEN")

CHALLENGES_ROOT_SUBNET = os.getenv("CHALLENGES_ROOT_SUBNET", "10.128.0.0")
CHALLENGES_ROOT_SUBNET_MASK = os.getenv("CHALLENGES_ROOT_SUBNET_MASK", "255.128.0.0")

time_start = datetime.datetime.now()

def uninstall():
    if input("Are you sure you want to uninstall CTF Challenger? (type 'uninstall' to confirm): ").strip().lower() != "uninstall":
        print("Uninstallation aborted.")
        return

    print("\nRemoving cleanup service")
    remove_cleanup_service()

    print("\nStopping backend service")
    stop_backend_service()

    print("\nResetting iptables rules")
    reset_iptables_rules()

    print("\nRemoving web and database server")
    remove_web_and_database_server()

    print("\nRemoving openvpn server")
    remove_openvpn_server()

    print("\nRemoving backend dnsmasq service")
    remove_backend_dnsmasq_service()

    print("\nRemoving .env files")
    remove_env_files()

    print("\nRemoving backend network")
    remove_backend_network()

    print("\nRemoving API tokens")
    remove_api_tokens()

    print("\nDeleting backend certificate")
    delete_backend_certificate()

def remove_cleanup_service():
    print("\tStopping and disabling cleanup service")
    subprocess.run(["systemctl", "stop", "ctf-challenger-cleanup.service"], capture_output=True)
    subprocess.run(["systemctl", "disable", "ctf-challenger-cleanup.service"], capture_output=True)

    print("\tRemoving cleanup service file")
    subprocess.run(["rm", "-f", f"{SYSTEMD_PATH}/cleanup.service"], capture_output=True)
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)


def stop_backend_service():
    print("\tStopping and disabling backend service")
    subprocess.run(["systemctl", "stop", "backend.service"], capture_output=True)
    subprocess.run(["systemctl", "disable", "backend.service"], capture_output=True)

    print("\tRemoving backend service file")
    subprocess.run(["rm", "-f", f"{SYSTEMD_PATH}/backend.service"], capture_output=True)


def reset_iptables_rules():
    print("\tResetting iptables rules")
    subprocess.run(["iptables", "-F"], capture_output=True)
    subprocess.run(["iptables", "-X"], capture_output=True)
    subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)
    subprocess.run(["iptables", "-t", "nat", "-X"], capture_output=True)

    print("\tStopping and removing iptables service")
    iptables_script_dir = "/etc/iptables-backend"
    subprocess.run(["systemctl", "stop", "iptables-backend.service"], capture_output=True)
    subprocess.run(["systemctl", "disable", "iptables-backend.service"], capture_output=True)
    subprocess.run(["rm", "-rf", IPTABLES_SERVICE_PATH], capture_output=True)
    subprocess.run(["rm", "-rf", iptables_script_dir], capture_output=True)


def remove_web_and_database_server():
    print("\tRemoving automatic server startup")
    subprocess.run(["systemctl", "stop", "start-vm.service"], capture_output=True)
    subprocess.run(["systemctl", "disable", "start-vm.service"], capture_output=True)
    subprocess.run(["rm", "-f", f"{SYSTEMD_PATH}/start-vm.service"], capture_output=True)

    print("\tRemoving servers")
    for vmid in [1000, 2000]:
        try:
            subprocess.run(["qm", "stop", str(vmid)], capture_output=True)
            subprocess.run(["qm", "destroy", str(vmid)], capture_output=True)
        except Exception:
            pass


def remove_openvpn_server():
    print("\tRemoving OpenVPN setup working directory")
    openvpn_setup_dir = "/root/ctf-challenger/setup/openvpn_setup"
    subprocess.run(["rm", "-rf", openvpn_setup_dir], capture_output=True)

    print("\tStopping and disabling OpenVPN service")
    subprocess.run(["systemctl", "stop", "openvpn@server"], capture_output=True)
    subprocess.run(["systemctl", "disable", "openvpn@server"], capture_output=True)

    print("\tRemoving OpenVPN configuration files")
    openvpn_config_dir = "/etc/openvpn/"
    subprocess.run(["rm", "-rf", openvpn_config_dir], capture_output=True)
    import os
    os.makedirs(openvpn_config_dir, exist_ok=True)



def remove_backend_dnsmasq_service():
    print("\tStopping and disabling backend dnsmasq service")
    try:
        with open("/etc/dnsmasq-backend/dnsmasq.pid", "r") as pid_file:
            pid = int(pid_file.read().strip())
            subprocess.run(["kill", str(pid)], capture_output=True)

    except FileNotFoundError:
        pass

    subprocess.run(["systemctl", "stop", "dnsmasq-backend.service"], capture_output=True)
    subprocess.run(["systemctl", "disable", "dnsmasq-backend.service"], capture_output=True)
    subprocess.run(["rm", "-f", DNSMASQ_SERVICE_PATH], capture_output=True)

    print("\tRestoring original dnsmasq configuration")
    subprocess.run(["systemctl", "enable", "dnsmasq"], capture_output=True)
    subprocess.run(["systemctl", "start", "dnsmasq"], capture_output=True)


def remove_env_files():
    print("\tRemoving .env files")
    env_files = [
        os.path.join(BACKEND_FILES_DIR, ".env"),
        os.path.join(WEBSERVER_FILES_DIR, ".env")
    ]

    for env_file in env_files:
        if os.path.exists(env_file):
            subprocess.run(["rm", "-f", env_file], capture_output=True)


def remove_backend_network():
    print("\tRemoving backend network")
    try:
        proxmox = ProxmoxAPI(PROXMOX_HOST, user=PROXMOX_USER, password=PROXMOX_PASSWORD, verify_ssl=False)
        proxmox.nodes(PROXMOX_HOSTNAME).network.delete(BACKEND_NETWORK_DEVICE)
        proxmox.nodes(PROXMOX_HOSTNAME).network.put()
    except Exception:
        pass


def remove_api_tokens():
    print("\tRemoving API tokens")
    try:
        proxmox = ProxmoxAPI(PROXMOX_HOST, user=PROXMOX_USER, password=PROXMOX_PASSWORD, verify_ssl=False)
        proxmox.access.users(PROXMOX_USER).token("backend-token").delete()
    except Exception:
        pass


def delete_backend_certificate():
    print("\tDeleting backend certificate")
    if os.path.exists(BACKEND_CERTIFICATE_FILE):
        subprocess.run(["rm", "-f", BACKEND_CERTIFICATE_FILE], capture_output=True)
    if os.path.exists(BACKEND_CERTIFICATE_KEY_FILE):
        subprocess.run(["rm", "-f", BACKEND_CERTIFICATE_KEY_FILE], capture_output=True)


if __name__ == "__main__":
    uninstall()
    time_end = datetime.datetime.now()
    print(f"\nUninstallation completed in {time_end - time_start}.")