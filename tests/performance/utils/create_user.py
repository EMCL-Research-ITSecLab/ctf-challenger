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

SIGNUP_URL = f"{SERVER_PROTOCOL}://{SERVER_HOST}:{SERVER_PORT}/backend/signup.php"
CSRF_TOKEN_URL = f"{SERVER_PROTOCOL}://{SERVER_HOST}:{SERVER_PORT}/views/signup.php"


def create_user(username, email, password, prints=False):
    if prints:
        print(f"\tInitiating session")
    session = requests.Session()
    session.verify = download_certificate()

    if prints:
        print(f"\tRetrieving CSRF token")
    response = session.get(CSRF_TOKEN_URL)  # Get CSRF token cookie
    beautifulsoup = BeautifulSoup.BeautifulSoup(response.text, "html.parser")
    csrf_token = beautifulsoup.find("input", {"name": "csrf_token"})["value"]

    if prints:
        print(f"\tCreating user {username} with email {email}")
    params = {
        "username": username,
        "email": email,
        "password": password,
        "confirm-password": password,
        "csrf_token": csrf_token
    }

    response = session.post(SIGNUP_URL, data=params)
    if response.status_code != 200 or not response.json().get("success"):
        raise Exception(f"Failed to create user {username}: {response.text}")

    if prints:
        print(f"\tUser {username} created successfully")
        print("\tRetrieving CSRF token for authenticated session")

    csrf_token = session.cookies.get("csrf_token")
    session.headers.update({"X-CSRF-TOKEN": csrf_token})

    return session


if __name__ == "__main__":
    username = "testuser"
    password = "testpass"
    email = "test@test.test"
    create_user(username, email, password, prints=True)
