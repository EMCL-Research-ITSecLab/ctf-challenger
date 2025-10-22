from get_authenticated_session import get_authenticated_session
from dotenv import load_dotenv, find_dotenv
import os

env_file = find_dotenv()
load_dotenv(env_file)

SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = os.getenv("SERVER_PORT", "8000")
SERVER_PROTOCOL = os.getenv("SERVER_PROTOCOL", "https")

DELETE_USER_URL = f"{SERVER_PROTOCOL}://{SERVER_HOST}:{SERVER_PORT}/backend/profile.php"


def delete_user(username, password, prints=False):
    if prints:
        print(f"\tRetrieving authenticated session for user {username}")
    session = get_authenticated_session(username, password)

    if prints:
        print(f"\tSending delete request for user {username}")
    params = {
        "password": password
    }
    response = session.delete(DELETE_USER_URL, json=params)
    if response.status_code != 200 or not response.json().get("success"):
        raise Exception(f"Failed to delete user {username}: {response.text}")

    if prints:
        print(f"\tUser {username} deleted successfully")


if __name__ == "__main__":
    for i in range(50):
        try:
            username = "testuser_" + str(i+1)
            password = "testpass"
            print(f"Deleting user {username}")
            delete_user(username, password, prints=True)
            print()
        except Exception as e:
            print(f"Error for user {username}: {e}")
            print()
