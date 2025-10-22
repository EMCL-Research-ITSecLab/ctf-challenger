import os
from playwright.sync_api import sync_playwright
import sys

UTILS_DIR_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "utils"))
sys.path.append(UTILS_DIR_PATH)
from upload_diskfile_ui import upload_diskfile_ui
from delete_diskfile_ui import delete_diskfile_ui

def ui_diskfile_upload_and_removal_test(username, password, file_path, prints=False):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        if prints:
            print("Testing Disk File Upload via UI")
        upload_diskfile_ui(page, file_path, username, password, login=True, prints=prints)

        display_name = os.path.basename(file_path).split(".")[0]
        unmodified_chars = "-"
        display_name = "".join([c if c.isalnum() or c in unmodified_chars else "" for c in display_name])

        if prints:
            print("\nTesting Disk File Removal via UI")
        delete_diskfile_ui(page, display_name, login=False, prints=prints)

        context.close()
        browser.close()


if __name__ == "__main__":
    username = os.getenv("ADMIN_USER", "admin")
    password = os.getenv("ADMIN_PASSWORD")
    file_path = "D:\\DC-1\\DC-1\\DC-1.ova"

    ui_diskfile_upload_and_removal_test(username, password, file_path, prints=True)