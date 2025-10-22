import ssl
import os
from dotenv import load_dotenv, find_dotenv

env_file = find_dotenv()
load_dotenv(env_file)

def download_certificate(server_host=None, server_port=None, output_path=None, prints=False):
    if not server_host:
        server_host = os.getenv("SERVER_HOST", "localhost")
    if not server_port:
        server_port = os.getenv("SERVER_PORT", "8000")
    if not output_path:
        output_path = os.path.join(os.path.dirname(__file__), f"{server_host}.pem")

    if os.path.exists(output_path):
        if prints:
            print(f"\tCertificate already exists at {output_path}")
        return output_path

    if prints:
        print("\tDownloading server certificate")
    pem_cert = ssl.get_server_certificate((server_host, int(server_port)))

    with open(output_path, "w") as cert_file:
        cert_file.write(pem_cert)

    return output_path


if __name__ == "__main__":
    download_certificate(prints=True)
