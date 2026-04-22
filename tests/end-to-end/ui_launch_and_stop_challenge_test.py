import os
from playwright.sync_api import sync_playwright
from utils.launch_challenge_ui import launch_challenge_ui
from utils.stop_challenge_ui import stop_challenge_ui
from utils.create_user_ui import create_user_ui
from utils.delete_user_ui import delete_user_ui

def ui_launch_and_stop_challenge_test(username, password, challenge_name, prints=False):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        if prints:
            print("Testing Challenge Launch via UI")
        launch_challenge_ui(page, challenge_name, username, password, login=True, prints=prints)

        if prints:
            print("\nTesting Challenge Stop via UI")
        stop_challenge_ui(page, challenge_name, login=False, prints=prints)

        context.close()
        browser.close()


if __name__ == "__main__":
    username = "testuser"
    email = "test@test.test"
    password = "testpass"

    challenge_name = "HeiJack - Prototype"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        create_user_ui(page, username, email, password, prints=False)

        context.close()
        browser.close()

    ui_launch_and_stop_challenge_test(username, password, challenge_name, prints=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        delete_user_ui(page, username, password, login=True, prints=False)

        context.close()
        browser.close()


