import requests
from dotenv import load_dotenv, find_dotenv
import os

env_file = find_dotenv()
load_dotenv(env_file)

SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = os.getenv("SERVER_PORT", "8000")
SERVER_PROTOCOL = os.getenv("SERVER_PROTOCOL", "https")

LAUNCH_CHALLENGE_URL = f"{SERVER_PROTOCOL}://{SERVER_HOST}:{SERVER_PORT}/backend/challenge.php"

def launch_challenge(session, challenge_id, prints=False):

    if prints:
        print(f"\tLaunching challenge ID {challenge_id}")
    params = {
        "action": "deploy",
        "challenge_id": challenge_id
    }
    response = session.post(LAUNCH_CHALLENGE_URL, json=params)

    if response.status_code != 200 or not response.json().get("success"):
        raise Exception(f"Failed to launch challenge ID {challenge_id}: {response.text}")
    if prints:
        print(f"\tChallenge ID {challenge_id} launched successfully")


if __name__ == "__main__":
    from get_authenticated_session import get_authenticated_session

    username = "testuser"
    password = "testpass"
    challenge_id = "2"

    session = get_authenticated_session(username, password)
    launch_challenge(session, challenge_id, prints=True)
