import os
from dotenv import load_dotenv, find_dotenv

env_file = find_dotenv()
load_dotenv(env_file)

SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = os.getenv("SERVER_PORT", "443")
SERVER_PROTOCOL = os.getenv("SERVER_PROTOCOL", "https")

BASE_URL = f"{SERVER_PROTOCOL}://{SERVER_HOST}:{SERVER_PORT}"


def login_user_ui(page, username, password, prints=False):
    if prints:
        print(f"\tNavigating to home page")
    page.goto(BASE_URL)

    if prints:
        print(f"\tNavigating to login page")
    login_link = page.locator('a:has-text("Login")')
    login_link.click()

    if prints:
        print(f"\tWaiting for login page to load")
    page.wait_for_load_state("networkidle")

    if prints:
        print(f"\tFilling login form for user {username}")
    page.fill('input[name="username"]', username)
    page.fill('input[name="password"]', password)

    if prints:
        print(f"\tSubmitting login form")
    page.click('button[type="submit"]')

    if prints:
        print(f"\tWaiting for navigation after login")
    page.wait_for_load_state("networkidle")

    page.wait_for_url("**/dashboard", timeout=10000)
