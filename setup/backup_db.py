import requests
from dotenv import load_dotenv
import os
from proxmoxer import ProxmoxAPI
import subprocess
import datetime
import time
import sys
import random

load_dotenv()

BACKEND_DIR = "/root/heiST/backend"
sys.path.append(BACKEND_DIR)

DATABASE_FILES_DIR = os.getenv("DATABASE_FILES_DIR", "/root/heiST/database")
DATABASE_NAME = os.getenv("DATABASE_NAME", "ctf_challenger")
DATABASE_USER = os.getenv("DATABASE_USER", "postgres")
DATABASE_HOST = os.getenv("DATABASE_HOST", "10.0.0.102")

DATABASE_BACKUP_DIR = "/root/heiST/database/backups"

def backup_database():
    """
    Backup the PostgreSQL database to a file.
    """
    if not os.path.exists(DATABASE_BACKUP_DIR):
        os.makedirs(DATABASE_BACKUP_DIR)


    common_name = get_common_name_for_backup()
    time_now = datetime.datetime.now()
    backup_filename = f"{DATABASE_NAME}_{time_now.strftime('%Y%m%d_%H%M%S')}_{common_name}.backup"
    backup_filepath = os.path.join(DATABASE_BACKUP_DIR, backup_filename)
    latest_backup_filepath = os.path.join(DATABASE_BACKUP_DIR, "latest.backup")

    print(f"\nGenerating backup for database '{DATABASE_NAME}'")
    tmp_backup_filepath = f"/tmp/{time.time()}.db.backup"
    subprocess.run(["ssh", f"{DATABASE_USER}@{DATABASE_HOST}", "pg_dump", "-F", "c", DATABASE_NAME, "-f", tmp_backup_filepath], check=True, capture_output=True)

    print(f"Transferring backup file from remote host to local machine")
    subprocess.run(["scp", f"{DATABASE_USER}@{DATABASE_HOST}:{tmp_backup_filepath}", backup_filepath], check=True, capture_output=True)
    subprocess.run(["cp", backup_filepath, latest_backup_filepath], check=True, capture_output=True)

    print(f"Deleting temporary backup file on remote host")
    subprocess.run(["ssh", f"{DATABASE_USER}@{DATABASE_HOST}", "rm", tmp_backup_filepath], check=True, capture_output=True)

    print(f"Backup completed successfully!\n")
    print(f"Time:\t\t\t{time_now.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Common Name:\t\t{common_name}")
    print(f"Backup File:\t\t{backup_filepath}\n")


def get_common_name_for_backup():
    """
    Prompt the user for a common name to use for the backup file or generate one.
    """
    while common_name := input("Enter a common name (alphanumeric + '_', max 20 chars) for the backup or press 'Enter' to generate one: ").strip():
        if len(common_name) <= 20 and all(c.isalnum() or c == '_' for c in common_name):
            return common_name

        if common_name == "":
            break

    adjectives = [
        "quick", "lazy", "happy", "sad", "angry", "excited", "bored", "curious",
        "clever", "brave", "calm", "bold", "bright", "cool", "daring", "eager",
    ]

    nouns = [
        "fox", "dog", "cat", "mouse", "rabbit", "squirrel", "bear", "lion",
        "tiger", "elephant", "giraffe", "zebra", "monkey", "panda", "koala", "penguin",
    ]

    adjective = random.choice(adjectives)
    noun = random.choice(nouns)
    common_name = f"{adjective}_{noun}"

    return common_name


if __name__ == "__main__":
    start_time = datetime.datetime.now()
    backup_database()
    end_time = datetime.datetime.now()
    print(f"\nDatabase backup completed in {end_time - start_time}.")