import sys
import os
from login_user_ui import login_user_ui
from upload_diskfile_ui import upload_all_diskfiles_ui

YAML_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../yaml"))
sys.path.append(YAML_DIR)
from yaml_parser import yaml_to_dict


def setup_challenge_ui(page, path_to_yaml, username=None, password=None, login=False, upload_ova_files=False, prints=False):
    if login:
        if not username or not password:
            raise ValueError("Username and password must be provided if login is True")
        login_user_ui(page, username, password, prints=prints)

    if upload_ova_files:
        if prints:
            print(f"\tUploading all OVA files for the challenge via UI")
        upload_all_diskfiles_ui(page, path_to_yaml, username, password, login=False, prints=prints)

    if prints:
        print(f"\tNavigating to Create Challenge page")
    menu_button = page.get_by_role("button", name="Menu")
    menu_button.click()
    add_challenge_button = page.get_by_role("link", name="Create CTF")
    add_challenge_button.click()

    if prints:
        print(f"\tWaiting for Add Challenge form to load")
    page.wait_for_load_state("networkidle")

    if prints:
        print(f"\tParsing YAML file {path_to_yaml} for challenge data")
    ctf = yaml_to_dict(path_to_yaml, prints=prints)
    print(ctf)

    if prints:
        print(f"\tFilling out the General Information tab")
    page.fill('input[name="ctf-name"]', ctf["name"])
    page.fill('textarea[name="ctf-description"]', ctf["description"])
    page.select_option('select[name="ctf-category"]', ctf["category"])
    page.select_option('select[name="ctf-difficulty"]', ctf["difficulty"])

    if prints:
        print(f"\tFilling out the Advanced Options tab")
    advanced_options_tab = page.locator("div[id='tab-advanced']")
    advanced_options_tab.click()

    page.fill('textarea[name="ctf-hint"]', ctf["hint"])
    page.fill('textarea[name="ctf-solution"]', ctf["solution"])

    if prints:
        print(f"\tSetting the Is Active checkbox to {ctf['isActive']}")

    is_active_checkbox = page.locator('input[name="ctf-is-active"]')
    is_active_checked = is_active_checkbox.is_checked()
    if ctf["isActive"] != is_active_checked:
        is_active_checkbox.click()


    if prints:
        print(f"\tSetting up the VMs")

    vms_tab = page.locator("button[id='tab-vm']")
    vms_tab.click()
    for vm in ctf["vms"]:
        if prints:
            print(f"\t\tAdding VM {vm['name']}")
        page.fill('input[name="vm-name"]', vm["name"])
        vm_option = page.locator(f'select[name="vm-ova"] option:has-text("{vm["ova_name"]}")')
        page.select_option('select[name="vm-ova"]', vm_option.get_attribute("value"))
        page.fill('input[name="vm-cores"]', str(vm["cores"]))
        page.fill('input[name="vm-ram"]', str(vm["ram_gb"]))
        page.fill('input[name="vm-ip"]', vm["domain_name"])
        add_vm_button = page.locator("button[type='submit']:has-text('Add VM')")
        add_vm_button.click()

    if prints:
        print(f"\tSetting up the Subnets")

    subnets_tab = page.locator("button[id='tab-subnet']")
    subnets_tab.click()
    for subnet in ctf["subnets"]:
        if prints:
            print(f"\t\tAdding Subnet {subnet['name']}")
        page.fill('input[name="subnet-name"]', subnet["name"])

        dmz_slider = page.locator("input[name='subnet-dmz'] + span")
        dmz_slider.click()

        accessible_slider = page.locator("input[name='subnet-accessible'] + span")
        accessible_slider.click()

        for vm_name in subnet["attached_vms"]:
            if prints:
                print(f"\t\t\tAttaching VM {vm_name} to Subnet {subnet['name']}")
            vm_checkbox = page.locator(f'div[class="vm-checkbox-item"] div[class="vm-checkbox-label"]:has-text("{vm_name}")')
            vm_checkbox.click()

        add_subnet_button = page.locator("button[type='submit']:has-text('Add Subnet')")
        add_subnet_button.click()

    if prints:
        print(f"\tSetting up the Flags")

    flags_tab = page.locator("button[id='tab-flag']")
    flags_tab.click()
    for flag in ctf["flags"]:
        if prints:
            print(f"\t\tAdding Flag {flag['flag']}")
        page.fill('input[name="flag-text"]', flag["flag"])
        page.fill('textarea[name="flag-description"]', flag["description"])
        page.fill('input[name="flag-points"]', str(flag["points"]))
        page.fill('input[name="flag-order"]', str(flag["order_index"]))
        add_flag_button = page.locator("button[type='submit']:has-text('Add Flag')")
        add_flag_button.click()

    if prints:
        print(f"\tSetting up the Hints")

    hints_tab = page.locator("button[id='tab-hint']")
    hints_tab.click()
    for hint in ctf["hints"]:
        if prints:
            print(f"\t\tAdding Hint {hint['hint_text']}")
        page.fill('textarea[name="hint-text"]', hint["hint_text"])
        page.fill('input[name="hint-points"]', str(hint["unlock_points"]))
        page.fill('input[name="hint-order"]', str(hint["order_index"]))
        add_hint_button = page.locator("button[type='submit']:has-text('Add Hint')")
        add_hint_button.click()

    if prints:
        print(f"\tSubmitting the Create Challenge form")

    submit_button = page.locator("button:has-text('Create CTF Challenge')")
    submit_button.click()

    if prints:
        print(f"\tWaiting for challenge creation to complete")

    confirmation_message = page.locator("text=Challenge created successfully")
    confirmation_message.wait_for(state="visible", timeout=1000 * 60 * 20)

    if prints:
        print(f"\tChallenge {ctf['name']} created successfully via UI")
        
    return ctf["name"]




