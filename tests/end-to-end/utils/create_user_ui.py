import os
from dotenv import load_dotenv, find_dotenv

env_file = find_dotenv()
load_dotenv(env_file)

SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = os.getenv("SERVER_PORT", "443")
SERVER_PROTOCOL = os.getenv("SERVER_PROTOCOL", "https")

BASE_URL = f"{SERVER_PROTOCOL}://{SERVER_HOST}:{SERVER_PORT}"

def create_user_ui(page, username, email, password, prints=False):
    if prints:
        print(f"\tNavigating to home page")
    page.goto(BASE_URL)

    if prints:
        print(f"\tNavigating to signup page")

    signup_link = page.get_by_role("banner").get_by_role("link", name="Get Started")
    signup_link.click()

    if prints:
        print(f"\tFilling signup form for user {username}")
    page.fill('input[name="username"]', username)
    page.fill('input[name="email"]', email)
    page.fill('input[name="password"]', password)
    page.fill('input[name="confirm-password"]', password)

    if prints:
        print(f"\tSubmitting signup form")
    page.click('button[type="submit"]')

    if prints:
        print(f"\tWaiting for navigation after signup")
    page.wait_for_load_state("networkidle")

    page.wait_for_url(f"**/dashboard", timeout=1000 * 10)

    if prints:
        print(f"\tUser {username} created successfully via UI")