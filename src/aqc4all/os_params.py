# aqc4all/os_params.py

import sys
import re
import os
import platform
import shutil
import subprocess

def detect_os(args):
    try:
        os_release_info = platform.freedesktop_os_release()
        if os_release_info.get('ID_LIKE'):
            os_id = [os_release_info.get('ID')] + os_release_info.get('ID_LIKE').split()
        else:
            os_id = [os_release_info.get('ID')]
        if os_id:
            return os_id
        else:
            print("ID field not found in /etc/os-release.")
            return None
    except OSError as e:
        print(f"Error reading os-release file: {e}")
        return None

def which_package_manager():
    # If we've missed any distros' package managers, add them to the list
    pkgmanagers = [
        'apt',
        'apk',
        'nix',
        'opkg',
        'xbps',
        'emerge',
        'pacman',
        'yay',
        'pamac',
        'yum',
        'dnf',
        'zypper',
        'flatpak',
        'snap',
        'brew',
    ]
    pkgmanlist = []

    for value in pkgmanagers:
        if shutil.which(value):
            pkgmanlist.append(value)

    if not pkgmanlist:
        print("[!] No recognized package managers found in PATH.")
        return None

    print("The following package managers have been detected in your PATH:")
    pkgmanlist_dict = {}
    i = 1
    for value in pkgmanlist:
        pkgmanlist_dict[str(i)] = value
        print(f"{i}) {value}")
        i += 1

    print("\nWhich one would you like to use to install dependencies?")
    confirm = input("Enter number or name: ").strip()

    while True:
        if confirm in pkgmanlist_dict.keys():
            return pkgmanlist_dict[confirm]
        elif confirm in pkgmanlist_dict.values():
            return confirm
        else:
            confirm = input("Unrecognised option.\nEnter number or name: ").strip()

def pkgmanager_commands(package_manager_name):
    pm_lower = package_manager_name.lower()

    if 'snap' in pm_lower:
        return {'name': 'snap', 'update_command': 'refresh', 'upgrade_command': 'refresh', 'install_command': 'install', 'remove_command': 'remove', 'force_command': '', 'yes_command': '-y'}
    elif 'apt' in pm_lower or 'apt-get' in pm_lower:
        return {'name': 'apt', 'update_command': 'update', 'upgrade_command': 'upgrade', 'install_command': 'install', 'remove_command': 'remove', 'force_command': '--force', 'yes_command': '-y'}
    elif 'dnf' in pm_lower:
        return {'name': 'dnf', 'update_command': 'update', 'upgrade_command': 'upgrade', 'install_command': 'install', 'remove_command': 'remove', 'force_command': '--force', 'yes_command': '-y'}
    elif 'yum' in pm_lower:
        return {'name': 'yum', 'update_command': 'update', 'upgrade_command': 'upgrade', 'install_command': 'install', 'remove_command': 'remove', 'force_command': '--force', 'yes_command': '-y'}
    elif 'pacman' in pm_lower or 'yay' in pm_lower or 'pamac' in pm_lower:
        return {'name': pm_lower, 'update_command': '-Sy', 'upgrade_command': '-Syu', 'install_command': '-S', 'remove_command': '-R', 'force_command': '--overwrite=*', 'yes_command': '--noconfirm'}
    elif 'emerge' in pm_lower:
        return {'name': 'emerge', 'update_command': '--sync', 'upgrade_command': '--upgrade', 'install_command': '', 'remove_command': '--deselect', 'force_command': '', 'yes_command': ''}
    elif 'apk' in pm_lower:
        return {'name': 'apk', 'update_command': 'update', 'upgrade_command': 'upgrade', 'install_command': 'add', 'remove_command': 'remove', 'force_command': '', 'yes_command': ''}
    elif 'zypper' in pm_lower:
        return {'name': 'zypper', 'update_command': 'update', 'upgrade_command': 'patch', 'install_command': 'install', 'remove_command': 'remove', 'force_command': '--force', 'yes_command': '-y'}
    # Template in case we've missed any package managers
    #elif '<package_manager>' in pm_lower:
    #    return {'name': '<name>', 'update_command': '<update>', 'upgrade_command': '<upgrade>', 'install_command': '<install>', 'remove_command': '<remove>', 'force_command': '<force>', 'yes_command': '<-y>'}
    else:
        return {'name': pm_lower, 'update_command': 'update', 'upgrade_command': 'upgrade', 'install_command': 'install', 'remove_command': 'remove', 'force_command': '', 'yes_command': '-y'}

def check_for_dependencies(args):
    browser_driver = None
    browser_arg = getattr(args, 'browser', None)

    # This is a list of all the browsers I know that can be controlled by
    # either geckodriver or chromedriver. This goes through the list in order
    # and stops when it finds a browser.
    # Feel free to add your browser to the list if it isn't there :-)
    browser_candidates = [
        (['firefox', 'firefox-esr', 'librewolf'], 'geckodriver'),
        (['chromium', 'google-chrome', 'chrome'], 'chromedriver'),
        (['brave', 'brave-browser'], 'chromedriver'),
        (['microsoft-edge', 'edge'], 'chromedriver'),
        (['vivaldi', 'vivaldi-stable'], 'chromedriver'),
        (['opera', 'opera-stable'], 'chromedriver'),
        (['tor-browser'], 'geckodriver'),  # Yes, if you really want to connect via TOR, you can!
    ]

    if browser_arg:
        # You can also explicitly specify what browser you want to use
        browser_choice = browser_arg.lower()
        if browser_choice in ['firefox', 'firefox-esr', 'librewolf', 'tor-browser']:
            browser_driver = 'geckodriver'
        elif browser_choice in ['chromium', 'google-chrome', 'chrome', 'brave', 'edge', 'vivaldi', 'opera']:
            browser_driver = 'chromedriver'
        else:
            print(f"Error: Specified browser '{browser_choice}' is not supported or recognized.")
            sys.exit(1)

        target_binaries = [browser_choice]
        if browser_choice == 'firefox':
            target_binaries = ['firefox', 'firefox-esr', 'librewolf']
        elif browser_choice == 'chromium':
            target_binaries = ['chromium', 'google-chrome', 'chrome']

        if not any(shutil.which(b) for b in target_binaries):
            print(f"Error: Specified browser '{browser_choice}' not found in PATH.")
            sys.exit(1)
    else:
        detected_browser = None
        for binaries, driver in browser_candidates:
            for binary in binaries:
                if shutil.which(binary):
                    detected_browser = binary
                    browser_driver = driver
                    break
            if detected_browser:
                print(f"[✓] Auto-detected browser: {detected_browser} (Driver: {browser_driver})")
                break

        if not browser_driver:
            print("Error: Could not find any supported web browser (Firefox, Chromium, Chrome, Brave, Edge, Vivaldi, Opera, etc.) in PATH.")
            print("Please install a supported browser or specify one using command-line arguments.")
            sys.exit(1)

    return browser_driver

def check_for_driver(args, browser_driver):
    if shutil.which(browser_driver):
        print(f"[✓] {browser_driver} is already installed.")
        return True

    print(f"[!] {browser_driver} not found in PATH.")

    # Crap, I forgot about NixOS...
    is_nixos = os.path.exists("/etc/NIXOS") or shutil.which("nix")

    if "geckodriver" in browser_driver:
        browser = "firefox"
    else:
        browser = "chromium"

    if is_nixos:
        print("\n[!] A-HA! NixOS environment detected!")
        print("    NixOS handles packages declaratively and uses a non-standard dynamic linker.")
        print("    (But given that you're running NixOS, I have no doubt you already knew that!)")
        print("    To run aqc4all successfully on NixOS, you have to execute it inside a nix-shell or add the driver:")
        print(f"    -> nix-shell -p {browser_driver} {browser} python3 ...")
        print("    Or make sure your flake.devShell includes the respective driver packages.")
        print("")
        print("    No, I cannot help you with this. It's above my pay grade,")
        print("    and if you DO need help, maybe you shouldn't be running NixOS...")
        sys.exit(1)

    proceed = input("Would you like to install it now? [Y/n]: ").strip().lower()
    if proceed in ['', 'y', 'yes', 'oh yeah baby!', 'hurry up']:
        pm_name = which_package_manager()
        if pm_name:
            # Pass only the two parameters expected by install_driver
            pm_config = pkgmanager_commands(pm_name)
            install_driver(browser_driver, pm_config)
    return False

def install_driver(browser_driver, package_manager):
    print(f"[*] Attempting to install {browser_driver} using {package_manager['name']}...")

    pm_name = package_manager['name']
    install_cmd = package_manager.get('install_command', '')
    yes_flag = package_manager.get('yes_command', '')

    pkg_map = {
        'geckodriver': {
            'emerge': 'net-misc/geckodriver',
            'apt': 'geckodriver',
            'pacman': 'geckodriver',
            'dnf': 'geckodriver',
            'zypper': 'geckodriver'
        },
        'chromedriver': {
            'emerge': 'www-client/chromium',
            'apt': 'chromium-chromedriver',
            'pacman': 'chromium',
            'dnf': 'chromium-chromedriver',
            'zypper': 'chromedriver'
        }
    }

    package_to_install = pkg_map.get(browser_driver, {}).get(pm_name, browser_driver)

    cmd = ['sudo', pm_name]
    if install_cmd:
        cmd.append(install_cmd)
    if yes_flag:
        cmd.append(yes_flag)
    # Only append the package to install if the atom/name is non-empty
    if package_to_install:
        cmd.append(package_to_install)

    try:
        result = subprocess.run(cmd, check=False)
        if result.returncode == 0:
            print(f"[✓] Successfully installed {browser_driver}!")
            return True
        else:
            print(f"[!] Installation unsuccessful. Exit code: {result.returncode}")
            return False
    except Exception as e:
        print(f"[!] Failed to execute installation command: {e}")
        return False
