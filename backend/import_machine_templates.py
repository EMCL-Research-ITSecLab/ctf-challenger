from hashlib import sha256
import random
import os
import subprocess
import time
import base64


from backend.qemu_ga_wrapper import GuestAgent, GuestAgentError
from backend.DatabaseClasses import MachineTemplate, ChallengeTemplate
from backend.proxmox_api_calls import (
    attach_cloud_init_drive,
    add_network_device_api_call,
    initial_configuration_api_call,
    launch_vm_api_call,
    shutdown_vm_api_call,
    vm_is_stopped_api_call,
    detach_cloud_init_drive,
    detach_network_device_api_call,
    convert_vm_to_template_api_call,
    delete_vm_api_call
)

def import_machine_templates(challenge_template_id, db_conn, ip_pool):
    """
    Import a machine template from a disk image file and associate it with a challenge.
    """
    print(f"[Info] Starting machine template import process for challenge template {challenge_template_id}", flush=True)
    start_time = time.time()

    try:
        print(f"[Info] Fetching challenge template {challenge_template_id} from database", flush=True)
        challenge_template = fetch_challenge_template(challenge_template_id, db_conn)
        print(f"[Info] Successfully fetched challenge template {challenge_template_id}", flush=True)

        print(f"[Info] Fetching machine templates for challenge {challenge_template_id}", flush=True)
        fetch_machine_templates(challenge_template, db_conn)
        print(f"[Info] Successfully fetched {len(challenge_template.machine_templates)} machine templates", flush=True)
    except Exception as e:
        print(f"[Error] Failed to fetch challenge template: {e}", flush=True)
        raise RuntimeError(f"Failed to fetch challenge template: {e}")

    try:
        print(f"[Info] Starting disk image import for {len(challenge_template.machine_templates)} machine templates", flush=True)
        import_disk_images_to_vm_templates(challenge_template)

        print(f"[Info] Configuring VMs for challenge {challenge_template_id}", flush=True)
        configure_vms(challenge_template, ip_pool)

        print(f"[Info] Converting machine template VMs to Proxmox templates", flush=True)
        convert_machine_template_vms_to_templates(challenge_template)

        print(f"[Info] Marking challenge template {challenge_template_id} as ready", flush=True)
        mark_challenge_template_as_ready(challenge_template, db_conn)

        elapsed_time = time.time() - start_time
        print(f"[Info] Machine template import completed successfully in {elapsed_time:.2f}s", flush=True)
    except Exception as e:
        print(f"[Error] Failed during import process: {e}", flush=True)
        print(f"[Info] Undoing machine template import for challenge {challenge_template_id}", flush=True)
        undo_import_machine_templates(challenge_template)
        raise RuntimeError(f"Failed to import disk images: {e}")


def fetch_challenge_template(challenge_id, db_conn):
    """
    Fetch the challenge details from the database.
    """
    print(f"[Debug] Querying database for challenge template {challenge_id}", flush=True)

    with db_conn.cursor() as cursor:
        cursor.execute("SELECT id FROM challenge_templates WHERE id = %s", (challenge_id,))
        result = cursor.fetchone()

    if result is None:
        print(f"[Error] Challenge template {challenge_id} not found in database", flush=True)
        raise ValueError(f"Challenge with ID {challenge_id} not found.")

    challenge_template = ChallengeTemplate(challenge_template_id=result[0])
    print(f"[Info] Successfully retrieved challenge template {challenge_id}", flush=True)

    return challenge_template


def fetch_machine_templates(challenge_template, db_conn):
    """
    Fetch the machine templates associated with the challenge from the database.
    """
    print(f"[Info] Fetching machine templates for challenge {challenge_template.id}", flush=True)

    machines_fetched = 0

    with db_conn.cursor() as cursor:
        cursor.execute("SELECT id, disk_file_path, cores, ram_gb "
                       "FROM machine_templates "
                       "WHERE challenge_template_id = %s", (challenge_template.id,))

        for machine_template_id, disk_file_path, cores, ram_gb in cursor.fetchall():
            print(f"[Debug] Processing machine template {machine_template_id}", flush=True)

            # Check if the disk file path is valid
            if not os.path.exists(disk_file_path):
                print(f"[Error] Disk file path does not exist: {disk_file_path}", flush=True)
                raise ValueError(f"Disk file path {disk_file_path} does not exist.")
            if not os.path.isfile(disk_file_path):
                print(f"[Error] Disk file path is not a file: {disk_file_path}", flush=True)
                raise ValueError(f"Disk file path {disk_file_path} is not a file.")
            if not disk_file_path.endswith(('.ova', '.iso')):
                print(f"[Error] Disk file path is not valid OVA or ISO: {disk_file_path}", flush=True)
                raise ValueError(f"Disk file path {disk_file_path} is not a valid OVA or ISO file.")

            print(f"[Info] Creating machine template {machine_template_id} with {cores} cores, {ram_gb}GB RAM", flush=True)
            print(f"[Debug] Disk file: {disk_file_path}", flush=True)

            machine_template = MachineTemplate(
                machine_template_id=machine_template_id,
                challenge_template=challenge_template
            )
            machine_template.set_cores(cores)
            machine_template.set_ram(ram_gb * 1024)  # Convert GB to MB
            machine_template.set_disk_file_path(disk_file_path)
            challenge_template.add_machine_template(machine_template)
            machines_fetched += 1
            print(f"[Info] Successfully added machine template {machine_template_id} to challenge", flush=True)

    print(f"[Info] Successfully fetched {machines_fetched} machine templates for challenge {challenge_template.id}", flush=True)


def check_user_input(user_input):
    """
    Sanitize user input to prevent command injection attacks.
    """
    import re

    blacklist_pattern = r"""[;&|><`$\\'"*?{}\[\]~!#()=]+"""
    if re.search(blacklist_pattern, user_input):
        print(f"[Error] Input validation failed - potentially dangerous characters detected", flush=True)
        raise ValueError("Input contains potentially dangerous characters.")

    print(f"[Debug] Input validation passed", flush=True)


def import_disk_images_to_vm_templates(challenge_template):
    """
    Import the disk images to VM templates.
    """
    print(f"[Info] Importing disk images for {len(challenge_template.machine_templates)} machine templates", flush=True)

    images_imported = 0
    for machine_template in challenge_template.machine_templates.values():
        disk_file_path = machine_template.disk_file_path
        print(f"[Info] Validating disk file for machine template {machine_template.id}", flush=True)
        check_user_input(disk_file_path)

        disk_file_extension = os.path.splitext(disk_file_path)[1].lower()
        print(f"[Debug] Disk file extension: {disk_file_extension}", flush=True)

        if disk_file_extension == ".ova":
            print(f"[Info] Converting OVA file to machine template {machine_template.id}", flush=True)
            convert_ova_to_machine_template(disk_file_path, machine_template.id)
            images_imported += 1

        elif disk_file_extension == ".iso":
            print(f"[Info] Converting ISO file to machine template {machine_template.id}", flush=True)
            convert_iso_to_machine_template(disk_file_path, machine_template.id)
            images_imported += 1

    print(f"[Info] Successfully imported {images_imported} disk images for challenge", flush=True)


def convert_ova_to_machine_template(disk_file_path, machine_template_id):
    """
    Convert an OVA disk image file to a machine template.
    """
    print(f"[Info] Starting OVA to machine template conversion for VM {machine_template_id}", flush=True)
    print(f"[Debug] OVA file path: {disk_file_path}", flush=True)

    tmp_dir_name = f"proxmox_import_{sha256(str(time.time()).encode() + b' ' + str(random.randint(0, 2**20)).encode()).hexdigest()}"

    tmp_dir = os.path.join("/tmp", tmp_dir_name)
    print(f"[Debug] Creating temporary extraction directory: {tmp_dir}", flush=True)
    os.makedirs(tmp_dir, exist_ok=True)

    # Extract the OVA file
    try:
        print(f"[Info] Extracting OVA file to {tmp_dir}", flush=True)
        subprocess.run(["tar", "-xvf", disk_file_path, "-C", tmp_dir], check=True, capture_output=True)
        print(f"[Info] OVA file extraction completed successfully", flush=True)
    except Exception as e:
        print(f"[Error] Failed to extract OVA file: {e}", flush=True)
        raise RuntimeError(f"Failed to extract OVA file: {e}")

    # Find the OVF file
    print(f"[Info] Searching for OVF file in extracted archive", flush=True)
    ovf_file_count = 0
    ovf_file = None
    for file in os.listdir(tmp_dir):
        if file.endswith(".ovf"):
            ovf_file = os.path.join(tmp_dir, file)
            ovf_file_count += 1
            print(f"[Debug] Found OVF file: {file}", flush=True)

    if not ovf_file:
        print(f"[Error] No OVF file found in OVA archive", flush=True)
        raise ValueError("No OVF file found in the OVA archive.")

    if ovf_file_count > 1:
        print(f"[Error] Multiple OVF files found: {ovf_file_count}", flush=True)
        raise ValueError("Multiple OVF files found in the OVA archive. Please provide a single OVF file.")

    # Convert the OVF file to a Proxmox template
    try:
        print(f"[Info] Importing OVF to Proxmox as machine template {machine_template_id}", flush=True)
        importovf_command = f"qm importovf {machine_template_id} '{ovf_file}' local-lvm"
        if "|" in importovf_command or ";" in importovf_command or "&" in importovf_command:
            print(f"[Error] Invalid characters in import command", flush=True)
            raise ValueError("Invalid characters in import command.")
        subprocess.run(importovf_command, shell=True, check=True, capture_output=True)
        print(f"[Info] OVF import completed successfully for machine template {machine_template_id}", flush=True)
    except Exception as e1:
        print(f"[Error] Failed to import OVF file: {e1}", flush=True)
        print(f"[Info] Cleaning up failed import - unlocking and destroying VM {machine_template_id}", flush=True)
        try:
            subprocess.run(["qm", "unlock", str(machine_template_id)], check=True, capture_output=True)
            subprocess.run(["qm", "destroy", str(machine_template_id)], check=True, capture_output=True)
            print(f"[Info] Cleanup completed for VM {machine_template_id}", flush=True)
        except Exception:
            pass

        raise RuntimeError(f"Failed to import OVA file: {e1}")

    # Clean up the temporary directory
    try:
        print(f"[Info] Removing temporary extraction directory: {tmp_dir}", flush=True)
        subprocess.run(["rm", "-rf", tmp_dir], check=True, capture_output=True)
        print(f"[Info] Temporary directory cleanup completed", flush=True)
    except Exception as e:
        print(f"[Error] Failed to clean up temporary directory: {e}", flush=True)
        raise RuntimeError(f"Failed to clean up temporary directory: {e}")


def convert_iso_to_machine_template(disk_file_path, machine_template_id):
    """
    Convert an ISO disk image file to a machine template.
    """
    print(f"[Info] Starting ISO to machine template conversion for VM {machine_template_id}", flush=True)
    print(f"[Debug] ISO file path: {disk_file_path}", flush=True)

    # Convert the ISO file to a Proxmox template
    try:
        if "|" in disk_file_path or ";" in disk_file_path or "&" in disk_file_path:
            print(f"[Error] Invalid characters in disk file path", flush=True)
            raise ValueError("Invalid characters in disk file path.")

        print(f"[Info] Importing ISO to Proxmox as machine template {machine_template_id}", flush=True)
        importdisk_command = f"qm importdisk {machine_template_id} \"{disk_file_path}\" local-lvm"
        subprocess.run(importdisk_command, shell=True, check=True, capture_output=True)
        print(f"[Info] ISO import completed successfully for machine template {machine_template_id}", flush=True)
    except Exception as e1:
        print(f"[Error] Failed to import ISO file: {e1}", flush=True)
        print(f"[Info] Cleaning up failed import - unlocking and destroying VM {machine_template_id}", flush=True)
        try:
            subprocess.run(["qm", "unlock", str(machine_template_id)], check=True, capture_output=True)
            subprocess.run(["qm", "destroy", str(machine_template_id)], check=True, capture_output=True)
            print(f"[Info] Cleanup completed for VM {machine_template_id}", flush=True)
        except Exception as e2:
            pass

        raise RuntimeError(f"Failed to import ISO file: {e1}")


def wait_for_cloud_init_completion(machine, timeout=600):
    """
    Wait until Cloud-init finishes and the setup script completes.
    Checks for a flag file created by the setup script and verifies systemd timer.
    """
    _PING_TIMEOUT = 120
    _CLOUD_INIT_EXEC_TIMEOUT = max(timeout - 180, 120) # 120+4*15=180
    _FAST_EXEC_TIMEOUT = 15

    checks = {
        'cloud_init': False,
        'bash_logging_timer': False,
        'setup_complete': False
    }

    start_time = time.monotonic()
    deadline = start_time + timeout

    with GuestAgent(vmid=machine.id) as ga:
        ping_deadline = time.monotonic() + _PING_TIMEOUT
        while not ga.ping():
            if time.monotonic() > ping_deadline:
                raise TimeoutError(
                    f"QEMU GA on VM {machine.id} did not become responsive within {_PING_TIMEOUT}s"
                )
            time.sleep(2)

        print(f"[Info] GA responsive on VM {machine.id}, starting cloud-init wait", flush=True)

        while time.monotonic() < deadline:
            elapsed = int(time.monotonic() - start_time)

            try:
                if not checks['cloud_init']:
                    result = ga.exec(
                        "cloud-init status",
                        capture_output=True,
                        timeout=_CLOUD_INIT_EXEC_TIMEOUT,
                    )
                    if result.exit_code == 0 or "done" in result.stdout.lower():
                        checks['cloud_init'] = True
                    else:
                        print(f"[{elapsed}s] cloud-init not done yet: {result.stdout.strip()!r}", flush=True)
                    time.sleep(10)
                    continue

                if not checks['bash_logging_timer']:
                    result = ga.exec(
                        ["systemctl", "is-active", "bash_loggin_timer.timer"],
                        capture_output=True,
                        timeout=_FAST_EXEC_TIMEOUT,
                    )
                    if result.stdout.strip() == "active":
                        checks['bash_logging_timer'] = True
                    else:
                        print(f"[{elapsed}s] bash_loggin_timer not active yet: {result.stdout.strip()!r}", flush=True)
                    time.sleep(10)
                    continue

                flag_result = ga.exec(
                    ["test", "-f", "/var/run/wazuh-setup-complete.flag"],
                    capture_output=False,
                    timeout=_FAST_EXEC_TIMEOUT,
                )
                timer_result = ga.exec(
                    ["systemctl", "is-active", "bash_loggin_timer.timer"],
                    capture_output=True,
                    timeout=_FAST_EXEC_TIMEOUT,
                )
                if flag_result.exit_code == 0 and timer_result.stdout.strip() == "active":
                    checks['setup_complete'] = True
                    time.sleep(15)  # stability buffer
                    return True
                else:
                    print(
                        f"[{elapsed}s] waiting for setup: "
                        f"flag={'present' if flag_result.exit_code == 0 else 'missing'} "
                        f"timer={timer_result.stdout.strip()!r}",
                        flush=True,
                    )

            except GuestAgentError as e:
                print(f"[{elapsed}s] Guest agent error for VM {machine.id}: {type(e).__name__}: {e}", flush=True)
            except Exception as e:
                print(f"[{elapsed}s] Unexpected error for VM {machine.id}: {type(e).__name__}: {e}", flush=True)

            time.sleep(10)

    incomplete = [k for k, v in checks.items() if not v]
    raise TimeoutError(
        f"Setup did not complete within {timeout}s for VM {machine.id}. Incomplete: {', '.join(incomplete)}")



def write_user_data_snippet(snippets_path="/var/lib/vz/snippets/user-data.yaml",
                            config_dir="/root/heiST/monitoring/wazuh/agent"):
    """
    Write a Cloud-Init user-data.yaml snippet with files encoded in Base64.
    Includes all files from config_dir/config/* and the .sh script.
    Returns the Proxmox volume path for cicustom.
    """
    print(f"[Info] Writing cloud-init user-data snippet to {snippets_path}", flush=True)
    print(f"[Debug] Config directory: {config_dir}", flush=True)

    os.makedirs(os.path.dirname(snippets_path), exist_ok=True)

    user_data_content = """#cloud-config
write_files:
"""

    files_to_include = []

    config_subdir = os.path.join(config_dir, "config")
    print(f"[Debug] Searching for files in {config_subdir}", flush=True)
    for root, dirs, files in os.walk(config_subdir):
        for fname in files:
            files_to_include.append(os.path.join(root, fname))
            print(f"[Debug] Found config file: {fname}", flush=True)

    setup_script = os.path.join(config_dir, "setup_wazuh.sh")
    if os.path.isfile(setup_script):
        files_to_include.append(setup_script)
        print(f"[Debug] Found setup script: setup_wazuh.sh", flush=True)

    print(f"[Info] Including {len(files_to_include)} files in cloud-init configuration", flush=True)

    files_encoded = 0
    for local_path in files_to_include:
        rel_path = os.path.relpath(local_path, config_dir)
        target_path = f"/var/monitoring/wazuh-agent/{rel_path}"

        target_path = target_path.replace("\\", "/")

        print(f"[Debug] Encoding file: {rel_path} -> {target_path}", flush=True)
        with open(local_path, "rb") as f:
            encoded = base64.b64encode(f.read()).decode("utf-8")

        user_data_content += f"""  - path: {target_path}
    owner: root:root
    permissions: '0755'
    encoding: b64
    content: |
      {encoded}
"""
        files_encoded += 1

    user_data_content += """bootcmd:
  - systemctl mask systemd-networkd-wait-online.service
runcmd:
  - apt-get update -y
  - DEBIAN_FRONTEND=noninteractive apt-get install -y curl wget
  - [ /var/monitoring/wazuh-agent/setup_wazuh.sh, --install , --yes ]
"""
    with open(snippets_path, "w") as f:
        f.write(user_data_content)

    print(f"[Info] Successfully wrote cloud-init configuration with {files_encoded} encoded files", flush=True)
    print(f"[Debug] User-data snippet path: local:snippets/user-data.yaml", flush=True)
    return "local:snippets/user-data.yaml"


def configure_vms(challenge_template, ip_pool):
    """
    Configure VMs with proper IP pool management.
    """
    print(f"[Info] Starting VM configuration for {len(challenge_template.machine_templates)} machines", flush=True)
    vms_configured = 0

    # Phase 1: VM Setup and Launch
    for machine_template in challenge_template.machine_templates.values():
        allocated_ip = None

        try:
            print(f"[Info] Configuring machine template {machine_template.id}", flush=True)
            allocated_ip = ip_pool.allocate_ip(machine_template.id)
            if not allocated_ip:
                print(f"[Error] Could not allocate IP for VM {machine_template.id}", flush=True)
                raise RuntimeError(f"Could not allocate IP for VM {machine_template.id}")

            print(f"[Debug] Allocated IP {allocated_ip} for VM {machine_template.id}", flush=True)

            print(f"[Debug] Attaching cloud-init drive to VM {machine_template.id}", flush=True)
            attach_cloud_init_drive(machine_template.id)

            print(f"[Debug] Writing cloud-init user-data snippet", flush=True)
            ci_custom_path = write_user_data_snippet()

            print(f"[Debug] Adding network device to VM {machine_template.id}", flush=True)
            add_network_device_api_call(machine_template.id)

            print(f"[Debug] Performing initial configuration for VM {machine_template.id}", flush=True)
            initial_configuration_api_call(machine_template, allocated_ip, ci_custom_path)

            print(f"[Info] Launching VM {machine_template.id}", flush=True)
            time.sleep(5)
            launch_vm_api_call(machine_template)
            vms_configured += 1
            print(f"[Info] VM {machine_template.id} launched successfully", flush=True)

        except Exception as e:
            print(f"[Error] Failed to configure VM {machine_template.id}: {e}", flush=True)
            raise RuntimeError(f"Failed to configure VM {machine_template.id}: {e}")

    print(f"[Info] Launched {vms_configured} VMs, waiting for cloud-init completion", flush=True)

    # Phase 2: Wait for completion and shutdown
    vms_completed = 0
    for machine_template in challenge_template.machine_templates.values():
        try:
            print(f"[Info] Waiting for cloud-init completion on VM {machine_template.id}", flush=True)
            wait_for_cloud_init_completion(machine_template)
            print(f"[Info] Cloud-init completed on VM {machine_template.id}, shutting down", flush=True)

            shutdown_vm_api_call(machine_template)
            max_wait = 900
            start_time = time.time()

            while time.time() - start_time < max_wait:
                if vm_is_stopped_api_call(machine_template):
                    print(f"[Info] VM {machine_template.id} shutdown completed", flush=True)
                    break
                elapsed = int(time.time() - start_time)
                if elapsed % 60 == 0:  # Log every 60 seconds
                    print(f"[Debug] Waiting for VM {machine_template.id} to stop ({elapsed}s elapsed)", flush=True)
                time.sleep(30)
            else:
                print(f"[Error] VM {machine_template.id} did not shut down within {max_wait}s", flush=True)
                raise RuntimeError(f"Cloud-init timed out for VM {machine_template.id}")

            print(f"[Debug] Detaching cloud-init drive from VM {machine_template.id}", flush=True)
            detach_cloud_init_drive(machine_template.id)

            print(f"[Debug] Detaching network device from VM {machine_template.id}", flush=True)
            detach_network_device_api_call(vmid=machine_template.id, nic="net30")

            print(f"[Debug] Releasing IP {ip_pool} for VM {machine_template.id}", flush=True)
            ip_pool.release_ip(machine_template.id)
            vms_completed += 1
            print(f"[Info] VM {machine_template.id} cleanup completed", flush=True)

        except Exception as e:
            print(f"[Error] Failed to complete cloud-init for VM {machine_template.id}: {e}", flush=True)
            raise

    print(f"[Info] Successfully completed configuration for {vms_completed} VMs", flush=True)


def convert_machine_template_vms_to_templates(challenge_template):
    """
    Convert the VM to a template in Proxmox.
    """
    print(f"[Info] Converting {len(challenge_template.machine_templates)} VMs to Proxmox templates", flush=True)
    templates_converted = 0

    for machine_template in challenge_template.machine_templates.values():
        try:
            print(f"[Info] Converting VM {machine_template.id} to template", flush=True)
            convert_vm_to_template_api_call(machine_template.id)
            templates_converted += 1
            print(f"[Info] Successfully converted VM {machine_template.id} to template", flush=True)
        except Exception as e:
            print(f"[Error] Failed to convert VM {machine_template.id} to template: {e}", flush=True)
            raise RuntimeError(f"Failed to convert VM to template: {e}")

    print(f"[Info] Successfully converted {templates_converted} VMs to templates", flush=True)


def mark_challenge_template_as_ready(challenge_template, db_conn):
    """
    Mark the challenge template as ready in the database.
    """
    print(f"[Info] Marking challenge template {challenge_template.id} as ready_to_launch in database", flush=True)

    with db_conn.cursor() as cursor:
        cursor.execute("UPDATE challenge_templates SET ready_to_launch = TRUE WHERE id = %s", (challenge_template.id,))
        db_conn.commit()

    print(f"[Info] Challenge template {challenge_template.id} successfully marked as ready", flush=True)


def undo_import_machine_templates(challenge_template):
    """
    Undo the import of machine templates.
    """
    print(f"[Error] Undoing machine template import for challenge {challenge_template.id}", flush=True)
    vms_deleted = 0

    for machine_template in challenge_template.machine_templates.values():
        try:
            print(f"[Info] Attempting to delete VM {machine_template.id}", flush=True)
            delete_vm_api_call(machine_template)
            vms_deleted += 1
            print(f"[Info] Successfully deleted VM {machine_template.id}", flush=True)
        except Exception as e:
            print(f"[Warning] Failed to delete VM {machine_template.id} via API: {e}", flush=True)
            try:
                print(f"[Debug] Attempting to unlock VM {machine_template.id}", flush=True)
                subprocess.run(["qm", "unlock", str(machine_template.id)], check=True, capture_output=True)
            except Exception:
                pass
            try:
                subprocess.run(["qm", "stop", str(machine_template.id)], check=True, capture_output=True)
            except Exception:
                pass
            try:
                print(f"[Debug] Attempting to destroy VM {machine_template.id}", flush=True)
                subprocess.run(["qm", "destroy", str(machine_template.id), "--skiplock"], check=True, capture_output=True)
                vms_deleted += 1
                print(f"[Info] Successfully destroyed VM {machine_template.id}", flush=True)
            except Exception as e3:
                print(f"[Warning] Failed to destroy VM {machine_template.id}: {e3}", flush=True)

    print(f"[Info] Cleanup completed - {vms_deleted} VMs deleted during undo process", flush=True)

