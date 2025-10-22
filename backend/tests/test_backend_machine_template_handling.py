import sys
import os
import time

BACKEND_DIR = "/root/ctf-challenger/backend"
TEST_UTILS_DIR = os.path.join(BACKEND_DIR, "tests", "utils")

sys.path.append(TEST_UTILS_DIR)
sys.path.append(BACKEND_DIR)

from mock_db import MockDatabase
from test_challenge_template_setup import test_plain_ubuntu_setup
from import_machine_templates import import_machine_templates
from delete_machine_templates import delete_machine_templates
from proxmox_api_calls import vm_exists_api_call, vm_is_template_api_call, get_sockets_api_call, get_memory_api_call
from check import check


def test_backend_machine_template_handling():
    """
    Test the import_machine_templates function.
    """

    print("\nTesting machine template handling")

    with MockDatabase() as db_conn:
        creator_id, challenge_template = test_plain_ubuntu_setup(db_conn)

        print(f"\tTesting machine template import")
        check(
            len(challenge_template.machine_templates) == 1,
            "\t\tChallenge template has one machine template",
            "\t\tChallenge template does not have one machine template"
        )
        machine_template = list(challenge_template.machine_templates.values())[0]

        try:
            # Import machine templates
            import_machine_templates(challenge_template.id, db_conn)

            check(
                vm_exists_api_call(machine_template),
                "\t\tMachine template VM exists after import",
                "\t\tMachine template VM does not exist after import"
            )

            import_dirs = os.listdir(f"/tmp/")
            check(
                len([d for d in import_dirs if d.startswith(f"proxmox_import")]) == 0,
                "\t\tAll temporary import directories cleaned up",
                "\t\tTemporary import directories not cleaned up"
            )
            check(
                vm_is_template_api_call(machine_template),
                "\t\tMachine template VM is a template",
                "\t\tMachine template VM is not a template"
            )
            check(
                machine_template.sockets == get_sockets_api_call(machine_template),
                "\t\tMachine template VM has correct number of sockets",
                "\t\tMachine template VM does not have correct number of sockets"
            )
            check(
                machine_template.ram == get_memory_api_call(machine_template),
                "\t\tMachine template VM has correct RAM size",
                "\t\tMachine template VM does not have correct RAM size"
            )

            print("\tMachine templates imported successfully")

        except Exception as e:
            print(f"\tFailed to import machine templates: {e}")

        finally:
            print("\tTesting machine template deletion")
            try:
                # Clean up user configuration
                delete_machine_templates(challenge_template.id, db_conn)
                check(
                    not vm_exists_api_call(challenge_template),
                    "\t\tMachine template VM deleted",
                    "\t\tMachine template VM still exists after deletion"
                )

                print("\tMachine template deleted successfully")

            except Exception as e:
                print(f"\tFailed to delete machine templates: {e}")
            finally:
                # Ensure the database connection is closed
                db_conn.close()


if __name__ == "__main__":
    test_backend_machine_template_handling()




