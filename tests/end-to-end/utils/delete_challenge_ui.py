from login_user_ui import login_user_ui


def delete_challenge_ui(page, challenge_name, username=None, password=None, login=False, prints=False):
    if login:
        if not username or not password:
            raise ValueError("Username and password must be provided if login is True")
        login_user_ui(page, username, password, prints=prints)

    if prints:
        print(f"\tNavigating to Manage Challenge page")
    menu_button = page.get_by_role("button", name="Menu")
    menu_button.click()
    manage_challenges_link = page.get_by_role("link", name="Manage CTFs")
    manage_challenges_link.click()

    if prints:
        print(f"\tWaiting for Manage Challenge page to load")

    page.wait_for_load_state("networkidle")

    if prints:
        print(f"\tSearching for challenge {challenge_name} to delete")

    challenge_row = page.locator(f'tr:has-text("{challenge_name}")')
    challenge_row.highlight()
    if not challenge_row:
        raise ValueError(f"Challenge {challenge_name} not found")

    if prints:
        print(f"\tClicking delete button for challenge {challenge_name}")

    delete_button = challenge_row.locator('button.delete')
    delete_button.click()

    if prints:
        print(f"\tSwitching to force deletion tab in confirmation modal")

    force_delete_tab = page.locator('button.tab-button:has-text("Force Delete")')
    force_delete_tab.click()

    if prints:
        print(f"\tConfirming deletion of challenge {challenge_name}")

    accept_confirm = lambda dialog: dialog.accept()

    page.on("dialog", accept_confirm)

    with page.expect_event("dialog") as dialog_info:
        confirm_delete_button = page.locator('button:has-text("Force Delete Now")')
        confirm_delete_button.click()

    if prints:
        print(f"\tWaiting for deletion confirmation message")

    confirmation_message = page.locator("text=Challenge and all instances deleted")
    confirmation_message.wait_for(state="visible", timeout=1000 * 10)

    if prints:
        print(f"\tChallenge {challenge_name} deleted successfully via UI")

    page.wait_for_load_state("networkidle")
