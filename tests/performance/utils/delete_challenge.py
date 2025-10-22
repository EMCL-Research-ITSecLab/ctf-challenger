import os
from dotenv import load_dotenv, find_dotenv

env_file = find_dotenv()
load_dotenv(env_file)

SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = os.getenv("SERVER_PORT", "8000")
SERVER_PROTOCOL = os.getenv("SERVER_PROTOCOL", "https")

DELETE_CHALLENGE_URL = f"{SERVER_PROTOCOL}://{SERVER_HOST}:{SERVER_PORT}/backend/manage-ctf.php"


def delete_challenge(admin_session, challenge_id, prints=False):
    if prints:
        print(f"\tDeleting challenge ID {challenge_id}")
    params = {
        "id": challenge_id,
         "force": True
    }

    response = admin_session.delete(DELETE_CHALLENGE_URL, json=params)

    if response.status_code != 200 or not response.json().get("success"):
        raise Exception(f"Failed to delete challenge ID {challenge_id}: {response.text}")

    if prints:
        print(f"\tChallenge ID {challenge_id} deleted successfully")


if __name__ == "__main__":
    from get_authenticated_session import get_authenticated_session

    challenge_id = "5"
    ADMIN_USER = os.getenv("ADMIN_USER", "admin")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

    session = get_authenticated_session(ADMIN_USER, ADMIN_PASSWORD)
    delete_challenge(session, challenge_id, prints=True)
