from login_user_ui import login_user_ui


def delete_user_ui(page, username=None, password=None, login=False, prints=False):
    if not password:
        raise ValueError("Password must be provided to delete a user")

    if login:
        if not username:
            raise ValueError("Username and password must be provided if login is True")

        login_user_ui(page, username, password, prints=prints)

    if prints:
        print(f"\tNavigating to Profile page")
    menu_button = page.get_by_role("button", name="Menu")
    menu_button.click()
    user_mgmt_link = page.get_by_role("link", name="Profile")
    user_mgmt_link.click()

    if prints:
        print(f"\tWaiting for Profile page to load")
    page.wait_for_load_state("networkidle")

    if prints:
        print(f"\tRemoving user {username}")

    if prints:
        print(f"\tSwitching to Security tab")
    security_tab = page.get_by_role("button", name="Security")
    security_tab.click()

    if prints:
        print(f"\tClicking Delete Account button")

    delete_user_button = page.get_by_role("button", name="Delete Account")
    delete_user_button.wait_for(state="visible", timeout=1000 * 60 * 5)
    delete_user_button.click()

    if prints:
        print(f"\tConfirming user deletion")

    password_input = page.locator('input[id="confirmPasswordForDeletion"]')
    password_input.fill(password)
    confirm_delete_button = page.get_by_role("button", name="Delete Account Permanently")
    confirm_delete_button.click()

    if prints:
        print(f"\tWaiting for navigation after user deletion")

    page.wait_for_load_state("networkidle")

    confirmation_message = page.locator("text=Account deleted successfully")
    confirmation_message.wait_for(state="visible", timeout=1000 * 10)

    if prints:
        print(f"\tUser {username} deleted successfully via UI")


