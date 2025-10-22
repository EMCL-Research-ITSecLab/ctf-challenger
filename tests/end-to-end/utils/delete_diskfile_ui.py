from login_user_ui import login_user_ui


def delete_diskfile_ui(page, display_name, username=None, password=None, login=False, prints=False):
    if login:
        if not username or not password:
            raise ValueError("Username and password must be provided if login is True")

        login_user_ui(page, username, password, prints=prints)

    if prints:
        print(f"\tNavigating to Disk Files page")
    menu_button = page.get_by_role("button", name="Menu")
    menu_button.click()
    diskfiles_link = page.get_by_role("link", name="Upload Diskfile")
    diskfiles_link.click()

    if prints:
        print(f"\tWaiting for Disk Files page to load")
    page.wait_for_load_state("networkidle")

    if prints:
        print(f"\tRemoving uploaded disk file")

    diskfile_container = page.locator(f'div.ova-item:has(div.ova-name:text-is("{display_name}"))')
    diskfile_container.wait_for(state="visible", timeout=1000 * 60 * 5)
    delete_button = diskfile_container.locator("div.ova-actions > button.delete-ova-btn")

    accept_dialog = lambda dialog: dialog.accept()
    page.on("dialog", accept_dialog)

    with page.expect_event("dialog") as dialog_info:
        delete_button.click()

    if prints:
        print(f"\tLooking for Disk File after deletion")

    page.locator(f'div:has-text("{display_name}")').first.wait_for(state="detached", timeout=1000 * 60 * 5)

    if prints:
        print(f"\tFile {display_name} removed successfully via UI")