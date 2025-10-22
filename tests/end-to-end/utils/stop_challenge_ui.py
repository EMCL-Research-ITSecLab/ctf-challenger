from login_user_ui import login_user_ui


def stop_challenge_ui(page, challenge_name, username=None, password=None, login=False, prints=False):
    if login:
        if not username or not password:
            raise ValueError("Username and password must be provided if login is True")

        login_user_ui(page, username, password, prints=prints)

    if prints:
        print(f"\tNavigating to Challenges page")
    menu_button = page.get_by_role("button", name="Menu")
    menu_button.click()
    challenges_link = page.get_by_role("link", name="Challenges")
    challenges_link.click()

    if prints:
        print(f"\tWaiting for Challenges page to load")
    page.wait_for_load_state("networkidle")

    if prints:
        print(f"\tSelecting challenge '{challenge_name}'")

    challenge_card = page.locator(f'div.ctf-card:has-text("{challenge_name}")')
    challenge_card.wait_for(state="visible", timeout=1000 * 60 * 5)
    challenge_card.click()

    if prints:
        print(f"\tWaiting for Challenge page to load")

    page.wait_for_load_state("networkidle")

    if prints:
        print(f"\tStopping challenge '{challenge_name}'")

    cancel_button = page.locator("button:has-text('Cancel Instance')")
    cancel_button.click()

    if prints:
        print(f"\tConfirming challenge stop")

    confirm_button = page.locator("button:has-text('Yes')")
    confirm_button.click()

    if prints:
        print(f"\tChecking if challenge '{challenge_name}' stopped successfully")
    launch_button = page.locator("button:has-text('Deploy Challenge')")
    launch_button.wait_for(state="visible", timeout=1000 * 60)

    page.wait_for_load_state("networkidle")

    if prints:
        print(f"\tChallenge '{challenge_name}' stopped successfully via UI")
