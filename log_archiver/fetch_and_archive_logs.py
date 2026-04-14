import os
import re
import sys
import paramiko
from stat import S_ISREG

# =========================
# CONFIGURATION CONSTANTS
# =========================

REMOTE_IP = "0.0.0.0"
SSH_KEYFILE = "/path/to/ssh/keyfile"

# Remote log directories to scan
REMOTE_LOG_DIRS = {
    "suricata_json": "/var/log/suricata/rotated/daily",
    "pcap": "/var/log/suricata/rotated/pcap",
    "database_backups": "/root/heiST/database/backups"
}

# Local base directory for archived logs
LOCAL_BASE_DIR = "/home/ubuntu/log-storage"

DATE_REGEX = re.compile(r"\d{4}-\d{2}-\d{2}")


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def connect_ssh(host: str, keyfile: str) -> paramiko.SSHClient:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=host,
        username="root",  # change if needed
        key_filename=keyfile
    )
    return ssh

def remove_remote_file(sftp: paramiko.SFTPClient, remote_path: str):
    try:
        sftp.remove(remote_path)
        print(f"[REMOVE] {remote_path}")
    except FileNotFoundError:
        print(f"[WARN] Remote file not found for removal: {remote_path}")


def validate_checksum(local_path: str, remote_path: str, ssh: paramiko.SSHClient) -> bool:
    stdin, stdout, stderr = ssh.exec_command(f"sha256sum '{remote_path}'")
    remote_checksum_line = stdout.readline().strip()
    if not remote_checksum_line:
        print(f"[ERROR] Could not retrieve checksum for remote file: {remote_path}")
        return False

    remote_checksum = remote_checksum_line.split()[0]

    import hashlib
    sha256 = hashlib.sha256()
    with open(local_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    local_checksum = sha256.hexdigest()

    if local_checksum == remote_checksum:
        print(f"[CHECKSUM OK] {local_path}")
        return True
    else:
        print(f"[CHECKSUM MISMATCH] {local_path}")
        return False


def fetch_gz_logs(ssh: paramiko.SSHClient):
    sftp = ssh.open_sftp()

    for log_type, remote_dir in REMOTE_LOG_DIRS.items():
        try:
            for entry in sftp.listdir_attr(remote_dir):
                if not S_ISREG(entry.st_mode):
                    continue

                filename = entry.filename
                if not filename.endswith(".gz"):
                    continue

                date_match = DATE_REGEX.search(filename)
                if not date_match:
                    print(f"[WARN] No date found in filename: {filename}")
                    continue

                log_date = date_match.group(0)

                local_dir = os.path.join(
                    LOCAL_BASE_DIR,
                    log_type,
                    log_date
                )
                ensure_dir(local_dir)

                local_path = os.path.join(local_dir, filename)
                remote_path = os.path.join(remote_dir, filename)

                if os.path.exists(local_path):
                    print(f"[EXISTS] {local_path}")
                    continue

                print(f"[FETCH] {remote_path} -> {local_path}")
                sftp.get(remote_path, local_path)

                if validate_checksum(local_path, remote_path, ssh):
                    print("[VALID] Checksum validated, removing remote file.")
                    remove_remote_file(sftp, remote_path)
                else:
                    print(f"[ERROR] Checksum validation failed for {local_path}. Remote file not deleted.")

        except FileNotFoundError:
            print(f"[WARN] Remote directory not found: {remote_dir}")

    sftp.close()

def main():
    ensure_dir(LOCAL_BASE_DIR)

    ssh = connect_ssh(REMOTE_IP, SSH_KEYFILE)
    try:
        fetch_gz_logs(ssh)
    finally:
        ssh.close()


if __name__ == "__main__":
    main()
