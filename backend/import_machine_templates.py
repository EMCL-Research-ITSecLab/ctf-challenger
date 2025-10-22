import subprocess
from proxmox_api_calls import *
from DatabaseClasses import MachineTemplate, ChallengeTemplate
from hashlib import sha256
import json
import time
import random

def import_machine_templates(challenge_template_id, db_conn, ip_pool):
    """
    Import a machine template from a disk image file and associate it with a challenge.
    """
    try:
        challenge_template = fetch_challenge_template(challenge_template_id, db_conn)

        fetch_machine_templates(challenge_template, db_conn)
    except Exception as e:
        raise RuntimeError(f"Failed to fetch challenge template: {e}")

    try:
        import_disk_images_to_vm_templates(challenge_template)

        configure_vms(challenge_template, ip_pool)

        convert_machine_template_vms_to_templates(challenge_template)
    except Exception as e:
        undo_import_machine_templates(challenge_template)
        raise RuntimeError(f"Failed to import disk images: {e}")


def fetch_challenge_template(challenge_id, db_conn):
    """
    Fetch the challenge details from the database.
    """
    with db_conn.cursor() as cursor:
        cursor.execute("SELECT id FROM challenge_templates WHERE id = %s", (challenge_id,))
        result = cursor.fetchone()

    if result is None:
        raise ValueError(f"Challenge with ID {challenge_id} not found.")

    challenge_template = ChallengeTemplate(challenge_template_id=result[0])

    return challenge_template


def fetch_machine_templates(challenge_template, db_conn):
    """
    Fetch the machine templates associated with the challenge from the database.
    """
    with db_conn.cursor() as cursor:
        cursor.execute("SELECT id, disk_file_path, cores, ram_gb "
                       "FROM machine_templates "
                       "WHERE challenge_template_id = %s", (challenge_template.id,))

        for machine_template_id, disk_file_path, cores, ram_gb in cursor.fetchall():
            # Check if the disk file path is valid
            if not os.path.exists(disk_file_path):
                raise ValueError(f"Disk file path {disk_file_path} does not exist.")
            if not os.path.isfile(disk_file_path):
                raise ValueError(f"Disk file path {disk_file_path} is not a file.")
            if not disk_file_path.endswith(('.ova', '.iso')):
                raise ValueError(f"Disk file path {disk_file_path} is not a valid OVA or ISO file.")

            machine_template = MachineTemplate(
                machine_template_id=machine_template_id,
                challenge_template=challenge_template
            )
            machine_template.set_cores(cores)
            machine_template.set_ram(ram_gb * 1024)  # Convert GB to MB
            machine_template.set_disk_file_path(disk_file_path)
            challenge_template.add_machine_template(machine_template)


def check_user_input(user_input):
    """
    Sanitize user input to prevent command injection attacks.
    """
    import re

    blacklist_pattern = r"""[;&|><`$\\'"*?{}\[\]~!#()=]+"""
    if re.search(blacklist_pattern, user_input):
        raise ValueError("Input contains potentially dangerous characters.")


def import_disk_images_to_vm_templates(challenge_template):
    """
    Import the disk images to VM templates.
    """
    for machine_template in challenge_template.machine_templates.values():
        disk_file_path = machine_template.disk_file_path
        check_user_input(disk_file_path)

        disk_file_extension = os.path.splitext(disk_file_path)[1].lower()

        if disk_file_extension == ".ova":
            convert_ova_to_machine_template(disk_file_path, machine_template.id)

        elif disk_file_extension == ".iso":
            convert_iso_to_machine_template(disk_file_path, machine_template.id)


def convert_ova_to_machine_template(disk_file_path, machine_template_id):
    """
    Convert an OVA disk image file to a machine template.
    """

    tmp_dir_name = f"proxmox_import_{sha256(str(time.time()).encode() + b' ' + str(random.randint(0, 2**20)).encode()).hexdigest()}"

    tmp_dir = os.path.join("/tmp", tmp_dir_name)
    os.makedirs(tmp_dir, exist_ok=True)

    # Extract the OVA file
    try:
        subprocess.run(["tar", "-xvf", disk_file_path, "-C", tmp_dir], check=True, capture_output=True)
    except Exception as e:
        raise RuntimeError(f"Failed to extract OVA file: {e}")

    # Find the OVF file
    ovf_file_count = 0
    ovf_file = None
    for file in os.listdir(tmp_dir):
        if file.endswith(".ovf"):
            ovf_file = os.path.join(tmp_dir, file)
            ovf_file_count += 1

    if not ovf_file:
        raise ValueError("No OVF file found in the OVA archive.")

    if ovf_file_count > 1:
        raise ValueError("Multiple OVF files found in the OVA archive. Please provide a single OVF file.")

    # Convert the OVF file to a Proxmox template
    try:
        importovf_command = f"qm importovf {machine_template_id} '{ovf_file}' local-lvm"
        if "|" in importovf_command or ";" in importovf_command or "&" in importovf_command:
            raise ValueError("Invalid characters in import command.")
        subprocess.run(importovf_command, shell=True, check=True, capture_output=True)
    except Exception as e1:
        try:
            subprocess.run(["qm", "unlock", str(machine_template_id)], check=True, capture_output=True)
            subprocess.run(["qm", "destroy", str(machine_template_id)], check=True, capture_output=True)
        except Exception:
            pass

        raise RuntimeError(f"Failed to import OVA file: {e1}")

    # Clean up the temporary directory
    try:
        subprocess.run(["rm", "-rf", tmp_dir], check=True, capture_output=True)
    except Exception as e:
        raise RuntimeError(f"Failed to clean up temporary directory: {e}")


def convert_iso_to_machine_template(disk_file_path, machine_template_id):
    """
    Convert an ISO disk image file to a machine template.
    """

    # Convert the ISO file to a Proxmox template
    try:
        if "|" in disk_file_path or ";" in disk_file_path or "&" in disk_file_path:
            raise ValueError("Invalid characters in disk file path.")

        importdisk_command = f"qm importdisk {machine_template_id} \"{disk_file_path}\" local-lvm"
        subprocess.run(importdisk_command, shell=True, check=True, capture_output=True)
    except Exception as e1:
        try:
            subprocess.run(["qm", "unlock", str(machine_template_id)], check=True, capture_output=True)
            subprocess.run(["qm", "destroy", str(machine_template_id)], check=True, capture_output=True)
        except Exception as e2:
            pass

        raise RuntimeError(f"Failed to import ISO file: {e1}")


def wait_for_cloud_init_completion(machine, timeout=600):
    """
    Wait until Cloud init finishes and the setup script completes.
    Checks for a flag file created by the setup script and verifies systemd timer.
    """
    start_time = time.time()
    checks = {
        'cloud_init': False,
        'bash_logging_timer': False,
        'setup_complete': False
    }

    while time.time() - start_time < timeout:
        elapsed = int(time.time() - start_time)

        try:
            # Phase 1: Cloud-init Status
            if not checks['cloud_init']:
                cmd = f"qm guest exec {machine.id} -- bash -c \"cloud-init status --wait\""
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)

                if "done" in result.stdout.lower() or result.returncode == 0:
                    checks['cloud_init'] = True
                    continue

            # Phase 2: Check for bash_loggin_timer.timer
            if checks['cloud_init'] and not checks['bash_logging_timer']:
                cmd = f"qm guest exec {machine.id} -- bash -c \"systemctl is-active bash_loggin_timer.timer 2>/dev/null\""
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)

                try:
                    result_data = json.loads(result.stdout)
                    status = result_data.get('out-data', '').strip()
                except:
                    status = result.stdout.strip()

                if status == "active":
                    checks['bash_logging_timer'] = True

            # Phase 3: Check for Setup-Complete Flag
            if checks['bash_logging_timer'] and not checks['setup_complete']:
                cmd = f"qm guest exec {machine.id} -- bash -c \"test -f /var/run/wazuh-setup-complete.flag && echo 'SETUP_COMPLETE'\""
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)

                try:
                    result_data = json.loads(result.stdout)
                    output = result_data.get('out-data', '').strip()
                except:
                    output = result.stdout.strip()

                if "SETUP_COMPLETE" in output:
                    checks['setup_complete'] = True

                    cmd_check = f"qm guest exec {machine.id} -- bash -c \"systemctl is-active bash_loggin_timer.timer 2>/dev/null\""
                    result_check = subprocess.run(cmd_check, shell=True, capture_output=True, text=True, timeout=30)

                    # Parse JSON output
                    try:
                        check_data = json.loads(result_check.stdout)
                        timer_status = check_data.get('out-data', '').strip()
                    except:
                        timer_status = result_check.stdout.strip()

                    if timer_status == "active":
                        # Extra buffer time to ensure everything is stable
                        time.sleep(15)
                        return True
                    else:
                        checks['setup_complete'] = False  # Reset to check again

        except subprocess.TimeoutExpired as e:
            print(f"[{elapsed}s] Command timeout for VM {machine.id}: {e}", flush=True)
        except subprocess.CalledProcessError as e:
            print(f"[{elapsed}s] Command failed for VM {machine.id}: {e}", flush=True)
        except Exception as e:
            print(f"[{elapsed}s] Unexpected error for VM {machine.id}: {type(e).__name__}: {e}", flush=True)

        time.sleep(10)

    # Timeout
    incomplete = [k for k, v in checks.items() if not v]
    raise TimeoutError(
        f"Setup did not complete within {timeout}s for VM {machine.id}. Incomplete: {', '.join(incomplete)}")


def write_user_data_snippet(snippets_path="/var/lib/vz/snippets/user-data.yaml",
                            config_dir="/root/ctf-challenger/monitoring/wazuh/agent"):
    """
    Write a Cloud-Init user-data.yaml snippet with files encoded in Base64.
    Includes all files from config_dir/config/* and the .sh script.
    Returns the Proxmox volume path for cicustom.
    """
    os.makedirs(os.path.dirname(snippets_path), exist_ok=True)

    user_data_content = """#cloud-config
packages:
  - curl
  - wget
write_files:
"""

    files_to_include = []

    config_subdir = os.path.join(config_dir, "config")
    for root, dirs, files in os.walk(config_subdir):
        for fname in files:
            files_to_include.append(os.path.join(root, fname))

    setup_script = os.path.join(config_dir, "setup_wazuh.sh")
    if os.path.isfile(setup_script):
        files_to_include.append(setup_script)

    for local_path in files_to_include:
        rel_path = os.path.relpath(local_path, config_dir)
        target_path = f"/var/monitoring/wazuh-agent/{rel_path}"

        target_path = target_path.replace("\\", "/")

        with open(local_path, "rb") as f:
            encoded = base64.b64encode(f.read()).decode("utf-8")

        user_data_content += f"""  - path: {target_path}
    owner: root:root
    permissions: '0755'
    encoding: b64
    content: |
      {encoded}
"""
    user_data_content += """bootcmd:
  - systemctl mask systemd-networkd-wait-online.service
runcmd:
  - [ /var/monitoring/wazuh-agent/setup_wazuh.sh, --install , --yes ]
"""
    with open(snippets_path, "w") as f:
        f.write(user_data_content)

    return "local:snippets/user-data.yaml"


def configure_vms(challenge_template, ip_pool):
    """
    Configure VMs with proper IP pool management.
    """
    for machine_template in challenge_template.machine_templates.values():
        allocated_ip = None

        try:
            allocated_ip = ip_pool.allocate_ip(machine_template.id)
            if not allocated_ip:
                raise RuntimeError(f"Could not allocate IP for VM {machine_template.id}")

            attach_cloud_init_drive(machine_template.id)
            ci_custom_path = write_user_data_snippet()
            add_network_device_api_call(machine_template.id)
            initial_configuration_api_call(machine_template, allocated_ip, ci_custom_path)
            time.sleep(5)
            launch_vm_api_call(machine_template)

        except Exception as e:
            raise RuntimeError(f"Failed to configure VM {machine_template.id}: {e}")

    for machine_template in challenge_template.machine_templates.values():
        wait_for_cloud_init_completion(machine_template)
        shutdown_vm_api_call(machine_template)
        max_wait = 900
        start_time = time.time()
        while time.time() - start_time < max_wait:
            if vm_is_stopped_api_call(machine_template):
                break
            time.sleep(30)
        else:
            raise RuntimeError(f"Cloud-init timed out for VM {machine_template.id}")

        detach_cloud_init_drive(machine_template.id)
        detach_network_device_api_call(vmid=machine_template.id, nic="net30")
        ip_pool.release_ip(machine_template.id)


def convert_machine_template_vms_to_templates(challenge_template):
    """
    Convert the VM to a template in Proxmox.
    """

    for machine_template in challenge_template.machine_templates.values():
        try:
            convert_vm_to_template_api_call(machine_template.id)
        except Exception as e:
            raise RuntimeError(f"Failed to convert VM to template: {e}")


def undo_import_machine_templates(challenge_template):
    """
    Undo the import of machine templates.
    """

    for machine_template in challenge_template.machine_templates.values():
        try:
            delete_vm_api_call(machine_template)
        except Exception:
            try:
                subprocess.run(["qm", "unlock", str(machine_template.id)], check=True, capture_output=True)
            except Exception:
                pass
            try:
                subprocess.run(["qm", "destroy", str(machine_template.id)], check=True, capture_output=True)
            except Exception:
                pass