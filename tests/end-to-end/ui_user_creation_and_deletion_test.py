import sys
import os
from playwright.sync_api import sync_playwright

UTILS_DIR_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "utils"))
sys.path.append(UTILS_DIR_PATH)
from create_user_ui import create_user_ui
from delete_user_ui import delete_user_ui
from login_user_ui import login_user_ui

def ui_user_creation_and_deletion_test(username, email, password, prints=False):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        if prints:
            print("Testing User Creation via UI")
        create_user_ui(page, username, email, password, prints=prints)


        if prints:
            print(f"\nTesting User Deletion via UI")

        delete_user_ui(page, username=username, password=password, login=False, prints=prints)

        if prints:
            print(f"\tChecking if user {username} was deleted successfully via UI")

        try:
            login_user_ui(page, username, password, prints=prints)
            raise Exception(f"User {username} was not deleted successfully via UI: Was able to log in after deletion")
        except Exception as e:
            print(f"\tUser {username} deleted successfully via UI: {str(e)}")

        context.close()
        browser.close()


if __name__ == "__main__":
    username = "testuser"
    email = "test@test.test"
    password = "testpass"
    ui_user_creation_and_deletion_test(username, email, password, prints=True)

