from proxmox_api_calls import delete_vm_api_call, stop_vm_api_call
from DatabaseClasses import ChallengeTemplate, MachineTemplate, Challenge, Machine
import subprocess


def delete_machine_templates(challenge_template_id, db_conn):
    """
    Delete the machine template VMs for a challenge.
    """

    try:
        challenge_template = fetch_challenge_and_machine_templates(challenge_template_id, db_conn)

        challenges = fetch_running_challenges_and_machines(challenge_template, db_conn)
    except Exception as e:
        raise ValueError(f"Error fetching challenge and machine templates: {str(e)}")

    stop_running_machines(challenges)

    delete_machines(challenges)

    delete_machine_template_vms(challenge_template)


def fetch_challenge_and_machine_templates(challenge_template_id, db_conn):
    """
    Fetch the machine template IDs for a challenge.
    """

    with db_conn.cursor() as cursor:
        cursor.execute("SELECT id FROM challenge_templates WHERE id = %s", (challenge_template_id,))

        result = cursor.fetchone()
        if result is None:
            raise ValueError(f"Challenge template with ID {challenge_template_id} not found.")

        challenge_template = ChallengeTemplate(challenge_template_id=challenge_template_id)

    with db_conn.cursor() as cursor:
        cursor.execute("SELECT id FROM machine_templates WHERE challenge_template_id = %s", (challenge_template.id,))

        for machine_template_id in cursor.fetchall():
            machine_template = MachineTemplate(
                machine_template_id=machine_template_id[0],
                challenge_template=challenge_template
            )
            challenge_template.add_machine_template(machine_template)

    return challenge_template


def fetch_running_challenges_and_machines(challenge_template, db_conn):
    """
    Fetch the running machine template instances for a challenge.
    """

    challenges = []

    with db_conn.cursor() as cursor:
        cursor.execute("SELECT id, subnet FROM challenges WHERE challenge_template_id = %s", (challenge_template.id,))

        for challenge_id, subnet in cursor.fetchall():
            challenge = Challenge(challenge_id=challenge_id, template=challenge_template, subnet=subnet)
            challenges.append(challenge)

    for challenge in challenges:
        for machine_template in challenge.template.machine_templates.values():
            with db_conn.cursor() as cursor:
                cursor.execute("SELECT id FROM machines WHERE challenge_id = %s AND machine_template_id = %s",
                               (challenge.id, machine_template.id))

                for machine_id in cursor.fetchall():
                    machine = Machine(machine_id=machine_id[0], template=machine_template, challenge=challenge)
                    challenge.add_machine(machine)

    return challenges


def stop_running_machines(challenges):
    """
    Stop the running machine template instances for a challenge.
    """

    for challenge in challenges:
        for machine in challenge.machines.values():
            try:
                stop_vm_api_call(machine)
            except Exception:
                continue


def delete_machines(challenges):
    """
    Delete the machine template instances for a challenge.
    """

    for challenge in challenges:
        for machine in challenge.machines.values():
            try:
                delete_vm_api_call(machine)
            except Exception:
                subprocess.run(["qm", "stop", str(machine.id)], check=False, capture_output=True)
                subprocess.run(["qm", "unlock", str(machine.id)], check=True, capture_output=True)
                subprocess.run(["qm", "destroy", str(machine.id)], check=True, capture_output=True)


def delete_machine_template_vms(challenge_template):
    """
    Delete the machine template VMs for a challenge.
    """

    for machine_template in challenge_template.machine_templates.values():
        try:
            delete_vm_api_call(machine_template)
        except Exception:
            subprocess.run(["qm", "stop", str(machine_template.id)], check=False, capture_output=True)
            subprocess.run(["qm", "unlock", str(machine_template.id)], check=True, capture_output=True)
            subprocess.run(["qm", "destroy", str(machine_template.id)], check=True, capture_output=True)
