import requests
from dotenv import load_dotenv, find_dotenv
import os
import bs4 as BeautifulSoup
from download_certificate import download_certificate

env_file = find_dotenv()
load_dotenv(env_file)

SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = os.getenv("SERVER_PORT", "8000")
SERVER_PROTOCOL = os.getenv("SERVER_PROTOCOL", "https")
SERVER_CERT_PATH = os.path.abspath(f"{SERVER_HOST}.pem")

LOGIN_URL = f"{SERVER_PROTOCOL}://{SERVER_HOST}:{SERVER_PORT}/backend/login.php"
CSRF_TOKEN_URL = f"{SERVER_PROTOCOL}://{SERVER_HOST}:{SERVER_PORT}/views/login.php"

def get_authenticated_session(username, password, prints=False):
    if prints:
        print("\tInitiating session")
    session = requests.Session()
    session.verify = download_certificate()

    if prints:
        print("\tRetrieving CSRF token")
    response = session.get(CSRF_TOKEN_URL)
    if response.status_code != 200:
        raise Exception(f"Failed to retrieve CSRF token: {response.text}")

    if prints:
        print("\tCrafting login request")
    params = {
        "username": username,
        "password": password
    }
    soup = BeautifulSoup.BeautifulSoup(response.text, "html.parser")
    csrf_token = soup.find("input", {"name": "csrf_token"})["value"]
    params["csrf_token"] = csrf_token

    if prints:
        print("\tSending login request")
    response = session.post(LOGIN_URL, data=params)

    if response.status_code != 200:
        raise Exception(f"Failed to log in user {username}: {response.text}")

    if prints:
        print("\tRetrieving CSRF token for authenticated session")
    csrf_token = response.json().get("csrf_token")
    session.headers.update({"X-CSRF-TOKEN": csrf_token})
    if prints:
        print("\tLogin successful")

    return session

if __name__ == "__main__":
    username = "testuser"
    password = "testpass"
    get_authenticated_session(username, password, prints=True)
