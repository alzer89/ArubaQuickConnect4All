# aqc4all/main.py

from . import login, config, certs, network, utils, os_params
import argparse
import sys
import textwrap
import re
import os


def parse_args():
    parser = argparse.ArgumentParser(
        description="Aruba QuickConnect 4 ALL (Linux Distros)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        This script will:
            - Automatically detect your installed and running network components
            - Perform authentication with an Aruba QuickConnect onboarding portal
            - Download and extract ArubaQuickConnect installer
            - Generate private key and certificate signing request
            - Enroll with the Aruba QuickConnect (EST) server
            - Output and persist configuration files for various network systems
            - Install config files and certs on request (or leave them in a folder for you)
            - Purge that Aruba filth from your glorious *-nix machine

        Supports:
        NetworkManager, wpa_supplicant, systemd-networkd, netifrc, connman, wicked, netctl

        This script SHOULD work on all POSIX-compliant OSes, but has only been tested on Linux.
        BSD Chads, you deserve some love too :-)
        """)
    )
    parser.add_argument("--portal", type=str, help="Specify portal URL")
    parser.add_argument("--username", type=str, help="Automatically input username")
    parser.add_argument("--password", type=str, help="Automatically input password (Do NOT use on untrusted machines!)")
    parser.add_argument("--totp-secret", type=str, help="Automatically input TOTP (Do NOT use on untrusted machines!)")
    parser.add_argument("--noinstall", action="store_true", help="Don't install generated config & certificates to your system")
    parser.add_argument("--browser", choices=["chromium", "firefox"], help="Supported browsers: Chromium, Firefox")
    parser.add_argument("--noclean", action="store_true", help="Do not clean /tmp/aqc after completion")
    parser.add_argument("--install-only", action="store_true", help="Install previously generated configs and certificates")
    parser.add_argument('--i-work-in-it', action="store_true", help="Special surprise for arrogant IT workers")
    parser.add_argument('--yes-i-know-i-am-root-and-know-what-i-am-doing', action="store_true", help="Only use this if you know what you are doing...")
    return parser.parse_args()


def check_for_dependencies(args):
    if firefox in args.browser:
        # Check for geckodriver in PATH
        pass
    elif chromium in args.browser:
        #Check for chromedriver in PATH
        pass
    else:
        # Throw an error


def check_for_root(args):
    if os.geteuid() == 0:
        if not args.yes_i_know_i_am_root_and_i_know_what_i_am_doing:
            print("This opens a WEB BROWSER.  And you were about to do it as root.\n\nThis is generally NOT a good idea...\n\n")
            print("Exiting...")
            sys.exit(1)
        else:
            print("You have added '--yes-i-know-i-am-root-and-i-know-what-i-am-doing'.\n\nYou brave, brave soul...\n\n")
            print("Are you 100% sure you want to proceed?")
            proceed = input("Continue? [y/N]: ").strip().lower()
            if proceed in ['y', 'Y', 'Yes', 'yEs', 'yeS', 'YES', 'yes', 'YES!', 'YOLO', 'Skibidi Rizz']:
                return 0
            else:
                sys.exit(1)
 
def check_for_required_fields(args):
    import getpass
    global USERNAME, PASSWORD, BASE_URL, TOTP_SECRET, BROWSER
    regex = re.compile(
            r'^(?:http|ftp)s?://' # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
            r'localhost|' #localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
            r'(?::\d+)?' # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    USERNAME = args.username
    while not USERNAME:
        USERNAME = input('Enter your username (REQUIRED): ')
    PASSWORD = args.password
    while not PASSWORD:
        PASSWORD = getpass.getpass(prompt='Enter your password (REQUIRED): ', stream=None)
    BASE_URL = args.portal
    while not BASE_URL:
        BASE_URL = input('Enter the onboarding portal URL (REQUIRED): ')
        BASE_URL = BASE_URL.strip('/')
        print(BASE_URL)
        if (re.match(regex, BASE_URL) is not None) == True:
            break
        else:
            print("Invalid URL!")
            BASE_URL = None
    TOTP_SECRET = args.totp_secret
    if not TOTP_SECRET:
        TOTP_SECRET = ""
    BROWSER = args.browser
    if not BROWSER:
        BROWSER = "firefox"

def special_surprise(args):
    if args.i_work_in_it:
        print("\033[95mWelcome to the secret BEANS mode!\033[0m")
        exit(0)

def install_only(args, extracted_data):
    if args.install_only:
        utils.prompt_to_install(args, extracted_data)
        exit(0)

def main():
    USER_AGENT = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
    created_configs = []
    extracted_data = {
            "username": None,
            "password": None,
            "root_cert": None,
            "client_cert": None,
            "priv_key": None,
            "ssid": None
            }
    args = parse_args()
    special_surprise(args)
    install_only(args, extracted_data)
    check_for_root(args)
    check_for_required_fields(args)
    #login.launch_browser(args, BROWSER) # This might actually be unnecessary
    url, cookies = login.perform_login_and_extract_gsid(args, USER_AGENT, BASE_URL, USERNAME, PASSWORD, TOTP_SECRET)
    login.download_script(url, cookies, USER_AGENT)
    login.extract_embedded_tar()
    config_values = config.read_config_variables()
    mac_wifi = utils.get_mac_address()
    if not mac_wifi:
        mac_wifi = "13:37:BE:EF:DE:AD"
    certs.post_device_metadata(config_values, BASE_URL, USER_AGENT, mac_wifi)
    certs.fetch_and_decode_cacerts(config_values, BASE_URL, USER_AGENT)
    certs.extract_credentials_from_plist(extracted_data)
    certs.extract_certs_from_plist(extracted_data)
    certs.fetch_and_parse_csrattrs(extracted_data, config_values, BASE_URL, USER_AGENT)
    certs.generate_private_key_if_missing(extracted_data)
    certs.generate_csr_from_key()
    certs.post_csr_request(config_values, BASE_URL, USER_AGENT, False)
    certs.process_csr_response(extracted_data)

    utils.display_wifi_client_info(extracted_data)

    network.generate_networkmanager_profile(created_configs, extracted_data)
    network.generate_wpa_supplicant_config(created_configs, extracted_data)
    network.generate_systemd_networkd_config(created_configs, extracted_data)
    network.generate_netifrc_config(created_configs, extracted_data)
    network.generate_apple_mobileconfig(created_configs, extracted_data)
    network.generate_android_wifi_config(created_configs, extracted_data)
    network.generate_netctl_config(created_configs, extracted_data)
    network.generate_connman_settings(created_configs, extracted_data)
    network.generate_wicked_config(created_configs, extracted_data)

    utils.persist_files(created_configs, extracted_data)
    utils.prompt_to_install(args, extracted_data)
    utils.cleanup_tmp(args)


if __name__ == "__main__":
    main()

