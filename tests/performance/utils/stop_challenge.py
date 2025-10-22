import os
from dotenv import load_dotenv, find_dotenv

env_file = find_dotenv()
load_dotenv(env_file)

SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = os.getenv("SERVER_PORT", "8000")
SERVER_PROTOCOL = os.getenv("SERVER_PROTOCOL", "https")

STOP_CHALLENGE_URL = f"{SERVER_PROTOCOL}://{SERVER_HOST}:{SERVER_PORT}/backend/challenge.php"

def stop_challenge(session, challenge_id, prints=False):
    if prints:
        print(f"\tStopping challenge ID {challenge_id}")

    params = {
        "action": "cancel",
        "challenge_id": challenge_id
    }

    response = session.post(STOP_CHALLENGE_URL, json=params)

    if response.status_code != 200 or not response.json().get("success"):
        raise Exception(f"Failed to stop challenge ID {challenge_id}: {response.text}")
    
    if prints:
        print(f"\tChallenge ID {challenge_id} stopped successfully")


if __name__ == "__main__":
    from get_authenticated_session import get_authenticated_session

    for i in range(10):
        try:
            username = "testuser_" + str(i+1)
            password = "testpass"
            challenge_id = "1"

            print(f"Stopping challenge for user {username}")
            session = get_authenticated_session(username, password, prints=True)
            stop_challenge(session, challenge_id, prints=True)
            print()
        except Exception as e:
            print(f"Error for user {username}: {e}")
            print()
