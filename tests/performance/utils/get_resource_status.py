import os
from dotenv import load_dotenv, find_dotenv
import requests
env_file = find_dotenv()
load_dotenv(env_file)

PROXMOX_API_HOST = os.getenv("PROXMOX_API_HOST", "localhost")
PROXMOX_API_PORT = os.getenv("PROXMOX_API_PORT", "8006")
PROXMOX_API_PROTOCOL = os.getenv("PROXMOX_API_PROTOCOL", "https")
PROXMOX_API_TOKEN = os.getenv("PROXMOX_API_TOKEN")
PROXMOX_HOSTNAME = os.getenv("PROXMOX_HOSTNAME", "pve")


def get_resource_status():
    url = f"{PROXMOX_API_PROTOCOL}://{PROXMOX_API_HOST}:{PROXMOX_API_PORT}/api2/json/nodes/{PROXMOX_HOSTNAME}/status"

    headers = {
        "Authorization": f"PVEAPIToken={PROXMOX_API_TOKEN}"
    }
    response = requests.get(
        url,
        headers=headers,
        verify=os.path.join(os.path.dirname(__file__), "pve-root-ca.pem"),
        timeout=5
    )

    if response.status_code == 200:
        return response.json()['data']
    else:
        raise Exception(f"Failed to get resource status: {response.status_code} - {response.text}")


if __name__ == "__main__":
    root_ca_cert = os.path.join(os.path.dirname(__file__), "pve-root-ca.pem")
    if not os.path.isfile(root_ca_cert):
        raise Exception(f"Root CA certificate not found at {root_ca_cert}. Please ensure the file exists.")


    status = get_resource_status()
    print(f"CPU Usage: {status['cpu'] * 100:.2f}%")
    print(f"RAM Usage: {status['memory']['used'] / status['memory']['total'] * 100:.2f}%")
