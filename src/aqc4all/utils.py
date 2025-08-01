import os
import shutil
import tempfile
import uuid
import getpass
import subprocess
import re
import time

def replace_string(filename, old_string, new_string):
    try:
        with open(filename, 'r') as file:
            file_content = file.read()

        if old_string not in file_content:
            print(f'"{old_string}" not found in {filename}. No replacement performed.')
            return

        modified_content = file_content.replace(old_string, new_string)

        with open(filename, 'w') as file:
            file.write(modified_content)
        print(f'Successfully replaced "{old_string}" with "{new_string}" in {filename}.')

    except FileNotFoundError:
        print(f'Error: File "{filename}" not found.')
    except Exception as e:
        print(f'An error occurred: {e}')

def detect_network_stack():
    tools = {
        "NetworkManager": shutil.which("nmcli"),
        "wpa_supplicant": shutil.which("wpa_supplicant"),
        "netctl": shutil.which("netctl"),
        "systemd-networkd": os.path.exists("/etc/systemd/network"),
        "connman": shutil.which("connmanctl"),
        "wicked": shutil.which("wicked"),
    }
    return {k: bool(v) for k, v in tools.items()}

def get_mac_address():
    try:
        output = subprocess.check_output(["ip", "link"], text=True)
        matches = re.findall(r"link/ether ([0-9a-f:]{17})", output)
        return matches[0] if matches else None
    except Exception as e:
        print(f"[!] Failed to obtain MAC address: {e}")
        return None

def build_est_payload(mac, otp):
    timestamp = int(time.time())
    payload = {
        "device_type": "Ubuntu",
        "id": 1,
        "network_interfaces": [
            {"interface_type": "Wireless", "mac_address": mac},
            {"interface_type": "Wired", "mac_address": "CA:FE:CO:FF:EE:99"}  # Placeholder second MAC
        ],
        "otp": otp,
        "timestamp": timestamp
    }
    return payload

def display_wifi_client_info(extracted_data):
    ssid = extracted_data['ssid']
    print("==========================")
    print("..:: wifi client info ::..")
    print("==========================")
    print(f"SSID: {ssid}")
    print("security: WPA / WPA2 Enterprise")
    print("key-mgmt: wpa-eap")
    print("eap: tls")
    print("phase2-auth: mschapv2")
    print(" ")
    print("User Name: in /tmp/aqc/payload1.plist")
    print("User Password: in /tmp/aqc/payload1.plist")
    print("client cert: /tmp/aqc/client.pem")
    print("private key: /tmp/aqc/private_key.pem")
    print(" ")
    print("ca cert: in /tmp/aqc/payload1.plist at bottom")
    print("==========================")

def persist_files(created_configs, extracted_data, target_dir=os.path.expanduser(f"~/")):
    print(f"[*] Copying files to persistent location: {target_dir}{extracted_data['ssid']}")
    target_dir = f"{target_dir}{extracted_data['ssid']}-files"
    os.makedirs(target_dir, exist_ok=True)

    try:
        # Copy the core certificates
        certs = {
            f"{extracted_data['client_cert']}": "client.pem",
            f"{extracted_data['priv_key']}": "private_key.pem",
            f"{extracted_data['root_cert']}": "ca_root.pem",
        }
        for src, name in certs.items():
            dst = os.path.join(target_dir, name)
            shutil.copy2(src, dst)
            print(f"[✓] {name} copied successfully to {dst}")
    except Exception as e:
        print(f"[!] Failed to copy certificate: {e}")

    # Copy all generated config files
    for file in created_configs:
        try:
            dst = os.path.join(target_dir, os.path.basename(file))
            shutil.copy2(file, dst)
            print(f"[✓] Config copied: {dst}")
        except Exception as e:
            print(f"[!] Failed to copy config {file}: {e}")

def detect_sudo_or_doas():
    # This prefers sudo over doas...for now...
    try:
        result = subprocess.run(['sudo', '-n', 'true'],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                check=False)
        if result.returncode == 0:
            return 'passwordless_sudo'
        else:
            return 'sudo'
    except FileNotFoundError:
        try:
            result = subprocess.run(['doas', '-C', '/etc/doas.conf', 'true'],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    check=False)
            if result.returncode == 0:
                return 'passwordless_doas'
            else:
                return 'doas'
        except FileNotFoundError:
            return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

def prompt_to_install(args, extracted_data):
    if not args.noinstall:
        detected = detect_network_stack()
        command = detect_sudo_or_doas()
        print("[*] Detected the following network stack:")
        for k, v in detected.items():
            if v:
                print(f" - {k}")
        print()
        print("This next part requires ROOT (sudo/doas) privileges")
        if 'passwordless' in command:
            print("IMPORTANT: You can already execute passwordless root commands.  Think carefully!")
        else:
            print("If you do not have this, you will not be able to install these configs")
        print("You can always, install these files manually, should you wish.")
        proceed = input("Continue? [y/N]: ").strip().lower()
        if proceed in ['y', 'Y', 'Yes', 'yEs', 'yeS', 'YES', 'yes', 'Yeah, why not...', 'Yes please']:
            if os.geteuid() != 0:
                try:
                    sdbinary = detect_sudo_or_doas()
                    if sdbinary == 'sudo' or sdbinary == 'doas':
                        if os.geteuid() != 0:
                            subprocess.run([ sdbinary, 'true' ])
                except:
                    print("Authentication unsuccessful.")
                    print(f"Configs and keys have been saved at ~/{extracted_data['ssid']}-files")
                    print("You can choose to manually install them at a later time if you wish.")
            for k, v in detected.items():
                if v:
                    proceed = input(f"Install config for {k}? [y/n]: ").strip().lower()
                    if proceed in ['y', 'Y', 'Yes', 'yEs', 'yeS', 'YES', 'yes']:
                        do_install(k, extracted_data, sdbinary)
        else:
            print("#################################")
            print("    Installation cancelled       ")
            print("#################################")
            print(f"All generated files have been saved to ~/{extracted_data['ssid']}-files/")
            print("You can always manually install them if you wish.")

def do_install(k, extracted_data, sdbinary):
    try:
        sdbinary = sdbinary.replace("passwordless_", "")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
    if k == "NetworkManager":
        install_networkmanager_config(extracted_data, sdbinary)
    elif k == "wpa_supplicant":
        install_wpa_supplicant_config(extracted_data, sdbinary)
    elif k == "netctl":
        install_netctl_config(extracted_data, sdbinary)
    elif k == "connman":
        install_connman_config(extracted_data, sdbinary)
    elif k == "wicked":
        install_wicked_config(extracted_data, sdbinary)
    else:
        print("[!] No supported network stack detected. You must be a hardcore Linux chad who runs LFS.  Mad respect...")

def install_certs_and_keys(extracted_data, config_file, install_path, extra_dirs, reload_command, sdbinary, append=False):
    try:
        ssid =  extracted_data['ssid']
        config_path = os.path.expanduser(f"~/{ssid}-files")
        newcert_path = '/etc/ssl/certs'
        newkey_path = '/etc/ssl/private'
        old_certs = ['ca_root.pem', 'client.pem']
        old_keys = [ 'private_key.pem']
        old_path = '/tmp/aqc'

        if extra_dirs:
            dirs = extra_dirs if isinstance(extra_dirs, list) else [extra_dirs]
            for directory in extra_dirs:
                subprocess.run([ sdbinary, 'mkdir', '-p', newcert_path, newkey_path, directory ], check=True)

        for v in old_certs:
            oldoldpath = f'{old_path}/{v}'
            oldpath = f'{config_path}/{v}'
            newpath =  f'{newcert_path}/{ssid}_{v}'
            replace_string(f'{config_path}/{config_file}', oldoldpath, newpath)
            subprocess.run([ sdbinary, 'cp', oldpath, newpath ])
            subprocess.run([ sdbinary, 'chown', 'root:root', newpath ])
            subprocess.run([ sdbinary, 'chmod', '600', newpath ])

        for v in old_keys:
            oldoldpath = f'{old_path}/{v}'
            oldpath = f'{config_path}/{v}'
            newpath =  f'{newkey_path}/{ssid}_{v}'
            replace_string(f'{config_path}/{config_file}', oldoldpath, newpath)
            subprocess.run([ sdbinary, 'cp', oldpath, newpath ], check=True)
            subprocess.run([ sdbinary, 'chown', 'root:root', newpath ], check=True)
            subprocess.run([ sdbinary, 'chmod', '600', newpath ], check=True)

        if append:
            subprocess.run([ sdbinary, 'sh', '-c', f'cat {config_path}/{config_file} >> {install_path}' ], check=True)
        else:
            subprocess.run([ sdbinary, 'cp', f'{config_path}/{config_file}', f'{install_path}' ], check=True)
            subprocess.run([ sdbinary, 'chmod', '600', f'{install_path}' ], check=True)
 
        subprocess.run( [sdbinary] + reload_command.split(), check=True)

    except PermissionError:
        print(f"Permission denied. Root privileges required.")
    except FileNotFoundError:
        print(f"Source file or destination directory not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


def install_networkmanager_config(extracted_data, sdbinary):
    ssid =  extracted_data['ssid']
    config_path = os.path.expanduser(f"~/{ssid}-files")
    config_file = f"{ssid}.nmconnection"
    install_path = f"/etc/NetworkManager/system-connections/{config_file}"
    extra_dirs = os.path.expanduser(f"~/.config/NetworkManager")
    reload_command = "nmcli connection reload"

    try:
        install_certs_and_keys(extracted_data, config_file, install_path, extra_dirs, reload_command, sdbinary, False)
        print(f"[✓] NetworkManager config installed to {config_path}")
    except Exception as e:
        print(f"[!] Failed to install NetworkManager config: {e}")

def install_wpa_supplicant_config(extracted_data, sdbinary):
    ssid =  extracted_data['ssid']
    install_path = "/etc/wpa_supplicant/wpa_supplicant.conf"
    config_path = os.path.expanduser(f"~/{ssid}-files")
    config_file = f"wpa_supplicant_{ssid}.conf"
    reload_command = "systemctl restart wpa_supplicant"
    extra_dirs = None

    try:
        install_certs_and_keys(extracted_data, config_file, install_path, extra_dirs, reload_command, sdbinary, True)
        print(f"[✓] wpa_supplicant config appended to {config_path}")
    except Exception as e:
        print(f"[!] Failed to install wpa_supplicant config: {e}")

def install_netctl_config(extracted_data, sdbinary):
    ssid =  extracted_data['ssid']
    install_path = "/etc/netctl/{ssid}"
    config_path = os.path.expanduser(f"~/{ssid}-files")
    config_file = f"netctl_{ssid}"
    reload_command = f"netctl start {ssid}"
    extra_dirs = None

    try:
        install_certs_and_keys(extracted_data, config_file, install_path, extra_dirs, reload_command, sdbinary, False)
        print(f"[✓] netctl config installed to {config_path}")
    except Exception as e:
        print(f"[!] Failed to install netctl config: {e}")

def install_connman_config(extracted_data, sdbinary):
    ssid =  extracted_data['ssid']
    config_path = os.path.expanduser(f"~/{ssid}-files")
    config_file = f"{ssid}.config"
    reload_command = "systemctl restart connman"
    install_path = f"/var/lib/connman/{ssid}.config"
    extra_dirs = None
    try:
        install_certs_and_keys(extracted_data, config_file, install_path, extra_dirs, reload_command, sdbinary, False)
        print(f"[✓] ConnMan config installed to {config_path}")
    except Exception as e:
        print(f"[!] Failed to install ConnMan config: {e}")

def install_wicked_config(extracted_data, sdbinary):
    ssid =  extracted_data['ssid']
    config_path = os.path.expanduser(f"~/{ssid}-files")
    config_file = f"wicked_{ssid}.xml"
    reload_command = "systemctl restart wicked"
    install_path = f"/etc/wicked/ifcfg-{ssid}"
    extra_dirs = None

    try:
        install_certs_and_keys(extracted_data, config_file, install_path, extra_dirs, reload_command, sdbinary, False)
        print(f"[✓] Wicked config installed to {config_path}")
    except Exception as e:
        print(f"[!] Failed to install Wicked config: {e}")

def cleanup_tmp(args):
    if not args.noclean:
        print("[*] Cleaning up temporary directory /tmp/aqc...")
        shutil.rmtree("/tmp/aqc", ignore_errors=True)
    else:
        print("[!] --noclean specified, leaving /tmp/aqc intact.")

