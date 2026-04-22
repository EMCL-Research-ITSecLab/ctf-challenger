import os
import sys
import subprocess
import time
import datetime
from dotenv import load_dotenv

load_dotenv()

from setup.backup_db import backup_database

DATABASE_NAME = os.getenv("DATABASE_NAME", "heist")
DATABASE_USER = os.getenv("DATABASE_USER", "postgres")
DATABASE_HOST = os.getenv("DATABASE_HOST", "10.0.0.102")

def restore_database(backup_file_path):
    """
    Restore a PostgreSQL database from the given backup file.
    """
    if not os.path.exists(backup_file_path):
        print(f"Error: Backup file '{backup_file_path}' does not exist.")
        sys.exit(1)

    confirm = input(f"This will overwrite the current contents of the database '{DATABASE_NAME}'.\nType 'overwrite' to confirm: ").strip().lower()
    if confirm != "overwrite":
        print("Restore operation cancelled.")
        sys.exit(0)

    print("Transferring backup file to remote host")
    remote_tmp_path = f"/tmp/{time.time()}.restore.backup"
    subprocess.run(["scp", backup_file_path, f"{DATABASE_USER}@{DATABASE_HOST}:{remote_tmp_path}"], check=True,
                   capture_output=True)
    
    print("\nCreating backup of current database before restoring")
    backup_database()

    time_now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"\nStarting restoring the database")

    print(f"Restoring database '{DATABASE_NAME}'")
    restore_cmd = f"pg_restore -U {DATABASE_USER} -d {DATABASE_NAME} --clean --no-owner {remote_tmp_path}"
    subprocess.run(["ssh", f"{DATABASE_USER}@{DATABASE_HOST}", restore_cmd], check=True)

    print("Cleaning up temporary file on remote host")
    subprocess.run(["ssh", f"{DATABASE_USER}@{DATABASE_HOST}", f"rm {remote_tmp_path}"], check=True)

    print(f"\nDatabase restore completed successfully.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <backup_file_path>")
        sys.exit(1)

    backup_file = sys.argv[1]
    start_time = datetime.datetime.now()
    restore_database(backup_file)
    end_time = datetime.datetime.now()
    print(f"Restore duration: {end_time - start_time}")
