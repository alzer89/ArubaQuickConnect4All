# aqc4all/os_params.py

import sys
import re
import os
import platform
import shutil

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
            'apk',
            'opkg',
            'xbps',
            'emerge',
            'pacman',
            'yay',
            'pamac',
            'yum',
            'zypper',
            'flatpak',
            'snap',
            'brew',
            ]
    pkgmanlist = []

    for value in pkgmanagers:
        if shutil.which(value):
            pkgmanlist.append(value)
    print("The following package managers have been detected in your PATH:")
    pkgmanlist_dict = {}
    i = 1
    for value in pkgmanlist:
        pkgmanlist_dict[str(i)] = value
        print(f"{i}) {value}")
        i += 1
    print(pkgmanlist_dict)
    print("\nWhich one would you like to use to install dependencies?")
    confirm = input("Enter number or name: ")
    response = None
    while not response:
        print(f"response: {response}")
        print(f"confirm: {confirm}")
        if confirm in pkgmanlist_dict.keys():
            response = pkgmanlist_dict[confirm]
        elif confirm in pkgmanlist_dict.values():
            response = confirm
        else:
            confirm = input("Unrecognised option.\nEnter number or name: ")
    return response

def pkgmanager_commands(args, package_manager):
    space = ' '
    os_id = list(package_manager)
    for value in os_id:    
        if 'snap' in value:
            package_manager = {
                    'name': ['snap', space],
                    'update_command': ['refresh', space],
                    'upgrade_command':['refresh', space],
                    'install_command': ['install', space],
                    'remove_command': ['remove', space],
                    'force_command': [space],
                    'yes_command': ['-y', space],
                    }
            break
     
        elif 'apt' in value:
            package_manager = {
                    'name': ['apt', space],
                    'update_command': ['update', space],
                    'upgrade_command': ['upgrade', space],
                    'install_command': ['install', space],
                    'remove_command': ['remove', space],
                    'force_command': ['--force', space],
                    'yes_command': ['-y', space],
                    }
            break
 
        elif 'dnf' in value:
            package_manager = {
                    'name': ['dnf', space],
                    'update_command': ['update', space],
                    'upgrade_command': ['upgrade', space],
                    'install_command': ['install', space],
                    'remove_command': ['remove', space],
                    'force_command': ['--force', space],
                    'yes_command': ['-y', space],
                    }
            break
 
        elif 'yum' in value:
            package_manager = {
                    'name': ['yum', space],
                    'update_command': ['update', space],
                    'upgrade_command': ['upgrade', space],
                    'install_command': ['install', space],
                    'remove_command': ['remove', space],
                    'force_command': ['--force', space],
                    'yes_command': ['-y', space],
                    }
            break

        elif 'pacman' in value:
            package_manager = {
                    'name': ['pacman', space],
                    'update_command': ['-Sy', space],
                    'upgrade_command': ['-Syu', space],
                    'install_command': ['-S', space],
                    'remove_command': ['-R', space],
                    'force_command': ['--overwrite=\\*', space],
                    'yes_command': ['--noconfirm', space],
                    }
            break
 
        elif 'emerge' in value:
            package_manager = {
                    'name': ['emerge', space],
                    'update_command': ['--sync', space],
                    'upgrade_command': ['--upgrade', space],
                    'install_command': [''],
                    'remove_command': ['--deselect', space],
                    'force_command': [''],
                    'yes_command': [''],
                    }
            break

        elif 'pkg' in value:
            package_manager = {
                    'name': ['pkg', space],
                    'update_command': ['update', space],
                    'upgrade_command': ['upgrade', space],
                    'install_command': ['install', space],
                    'remove_command': ['remove', space],
                    'force_command': ['--force', space],
                    'yes_command': ['-y', space],
                    }
            break

        elif 'xpbs' in value:
            package_manager = {
                    'name': ['xpbs-'],
                    'update_command': ['update', space],
                    'upgrade_command': ['upgrade', space],
                    'install_command': ['install', space],
                    'remove_command': ['remove', space],
                    'force_command': ['--force', space],
                    'yes_command': ['-y', space],
                    }
            break

        elif 'apk' in value:
            package_manager = {
                    'name': ['apk', space],
                    'update_command': ['update', space],
                    'upgrade_command': ['upgrade', space],
                    'install_command': ['add', space],
                    'remove_command': ['remove', space],
                    'force_command': [''],
                    'yes_command': [''],
                    }
            break

        elif 'opkg' in value:
            package_manager = {
                    'name': ['opkg', space],
                    'update_command': ['update', space],
                    'upgrade_command': [''],
                    'install_command': ['install', space],
                    'remove_command': ['remove', space],
                    'force_command': ['--force-reinstall', space],
                    'yes_command': [''],
                    }
            break

        elif 'zypper' in value:
            package_manager = {
                    'name': ['zypper', space],
                    'update_command': ['update', space],
                    'upgrade_command': ['patch', space],
                    'install_command': ['install', space],
                    'remove_command': ['remove', space],
                    'force_command': ['--force', space],
                    'yes_command': ['-y', space],
                    }
            break

# Template in case we've missed any package managers
#        elif '' in value:
#            package_manager = {
#                    'name': ['', space],
#                    'update_command': ['', space],
#                    'upgrade_command': ['', space],
#                    'install_command': ['', space],
#                    'remove_command': ['', space],
#                    'force_command': ['', space],
#                    'yes_command': ['-y', space],
#                    }
#            break

    return package_manager


def check_for_dependencies(args):
    browser_driver = None
    if 'firefox' in args.browser:
        try:
            if shutil.which('firefox'):
                browser_driver = 'geckodriver'
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)
        except:
            print("Unknown error occurred.")
            sys.exit(1)
    elif 'chromium' in args.browser:
        try:
            if shutil.which('chromium') or shutil.which('google-chrome'):
                browser_driver = 'chromedriver'
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)
        except:
            print("Unknown error occurred.")
            sys.exit(1)
    return browser_driver

def check_for_driver(args, browser_driver):
    try:
        if shutil.which(browser_driver):
            return True
    except:
        print(f"{browser_driver} not found.")
        proceed = input("Would you like to install it now? [Y/n]: ").strip().lower()
        if proceed in ['y', 'Y', 'Yes', 'yEs', 'yeS', 'YES', 'yes', 'OH YEAH BABY!', 'HURRY UP']:
            package_manager = which_package_manager()
            install_driver(args, package_manager, browser_driver)
 

def install_driver(args, package_manager, browser_driver):
    # Check for browser_driver in PATH
    if not shutil.which(browser_driver):
        try:
            cmd = ['sudo', package_manager['name'], package_manager['install_command'], 'geckodriver', package_manager['yes_command']]
            subprocess.run(cmd)
            return True
        except as e:
            print(f"Install unsuccessful: {e}")
            sys.exit(1)
    else:
        print("Already Installed")
        return True
