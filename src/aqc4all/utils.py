import os
import shutil
import tempfile
import uuid
import getpass
import subprocess
import re

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
    print("==========================")
    print("..:: wifi client info ::..")
    print("==========================")
    print(f"SSID: {extracted_data['ssid']}")
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

def prompt_to_install(args, extracted_data):
    if not args.noinstall:
        detected = detect_network_stack()
        print("[*] Detected the following network stack:")
        for k, v in detected.items():
            if v:
                print(f" - {k}")
        print()
        print("This next part requires ROOT (sudo) privileges")
        print("If you do not have this, you will not be able to install these configs")
        proceed = input("Continue? [y/N]: ").strip().lower()
        if proceed in ['y', 'Y', 'Yes', 'yEs', 'yeS', 'YES', 'yes', 'Yeah, why not...']:
            try:
                sudo_password = getpass.getpass(prompt='sudo password: ')
                p = subprocess.Popen(['sudo', '-S', 'ls'], stderr=subprocess.PIPE, stdout=subprocess.PIPE,  stdin=subprocess.PIPE)
                try:
                    out, err = p.communicate(input=(sudo_password+'\n').encode(),timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
            except:
                print("Authentication unsuccessful.")
                print(f"Configs and keys have been saved at ~/{extracted_data['ssid']}-files")
                print("You can choose to manually install them at a later time if you wish.")
            for k, v in detected.items():
                if v:
                    proceed = input(f"Install config for {k}? [y/n]: ").strip().lower()
                    if proceed in ['y', 'Y', 'Yes', 'yEs', 'yeS', 'YES', 'yes']:
                        do_install(k, extracted_data)

def do_install(k, extracted_data):
    if k == "NetworkManager":
        install_networkmanager_config(extracted_data)
    elif k == "wpa_supplicant":
        install_wpa_supplicant_config(extracted_data)
    elif k == "netctl":
        install_netctl_config(extracted_data)
    elif k == "connman":
        install_connman_config(extracted_data)
    elif k == "wicked":
        install_wicked_config(extracted_data)
    else:
        print("[!] No supported network stack detected. You must be a hardcore Linux chad who runs LFS.  Mad respect...")

def install_certs_and_keys(extracted_data, config_file, install_path, extra_dirs, reload_command, append=False):
    ssid =  extracted_data['ssid']
    config_path = os.path.expanduser(f"~/{ssid}-files")
    newcert_path = "/etc/ssl/certs"
    newkey_path = "/etc/ssl/private"
    old_certs = ['ca_root.pem', 'client.pem']
    old_keys = [ 'private_key.pem']

    if extra_dirs:
        os.makedirs(extra_dirs, exist_ok=True)

    for v in old_certs:
        oldpath = f'{config_path}/{v}'
        newpath =  f'{newcert_path}/{ssid}_{v}'
        replace_string(config_file, oldpath, newpath)
        shutil.copy2(oldpath, newpath)
        os.chmod(newpath, 0o600)

    for v in old_keys:
        oldpath = f'{old_path}/{v}'
        newpath =  f'{newkey_path}/{ssid}_{v}'
        replace_string(config_file, f'{old_path}/{old_file}', f'{newkey_path}/{ssid}_{v}')
        replace_string(config_file, oldpath, newpath)
        shutil.copy2(oldpath, newpath)
        os.chmod(newpath, 0o600)
    if apppend:
        f1 = open(install_path, 'a+')
        f2 = open(config_file, 'r')
        f1.write(f2.read())
        f1.close()
        f2.close()
    else:
        shutil.copy2(config_file, install_path)
        os.chmod(install_path, 0o600)
 
    subprocess.run(reload_command.split(), check=True)


def install_networkmanager_config(extracted_data):
    ssid =  extracted_data['ssid']
    config_path = os.path.expanduser(f"~/{ssid}-files")
    config_file = f"{config_path}/{ssid}.nmconnection"
    install_path = "/etc/NetworkManager/system-connections"
    extra_dirs = os.path.expanduser(f"~/.config/NetworkManager")
    reload_command = "sudo nmcli connection reload"

    try:
        install_certs_and_keys(extracted_data, config_file, install_path, extra_dirs, False)
        print(f"[✓] NetworkManager config installed to {config_path}")
    except Exception as e:
        print(f"[!] Failed to install NetworkManager config: {e}")

def install_wpa_supplicant_config():
    ssid =  extracted_data['ssid']
    install_path = "/etc/wpa_supplicant/wpa_supplicant.conf"
    config_path = os.path.expanduser(f"~/{ssid}-files")
    config_file = f"{config_path}/wpa_supplicant_{ssid}.conf"
    reload_command = "sudo systemctl restart wpa_supplicant"

    try:
        install_certs_and_keys(extracted_data, config_file, install_path, extra_dirs, True)
        print(f"[✓] wpa_supplicant config appended to {config_path}")
    except Exception as e:
        print(f"[!] Failed to install wpa_supplicant config: {e}")

def install_netctl_config():
    ssid =  extracted_data['ssid']
    config_install_path = "/etc/netctl/{ssid}"
    config_path = os.path.expanduser(f"~/{ssid}-files")
    config_file = f"{config_path}/netctl_{ssid}"
    reload_command = f"sudo netctl start {ssid}"

    try:
        install_certs_and_keys(extracted_data, config_file, install_path, extra_dirs, False)
        print(f"[✓] netctl config installed to {config_path}")
    except Exception as e:
        print(f"[!] Failed to install netctl config: {e}")

def install_connman_config():
    ssid =  extracted_data['ssid']
    config_path = os.path.expanduser(f"~/{ssid}-files")
    config_file = f"{config_path}/{ssid}.config"
    reload_command = "sudo systemctl restart connman"
    install_path = f"/var/lib/connman/{ssid}.config"
    try:
        install_certs_and_keys(extracted_data, config_file, install_path, extra_dirs, False)
        print(f"[✓] ConnMan config installed to {config_path}")
    except Exception as e:
        print(f"[!] Failed to install ConnMan config: {e}")

def install_wicked_config():
    ssid =  extracted_data['ssid']
    config_path = os.path.expanduser(f"~/{ssid}-files")
    config_file = f"{config_path}/wicked_{ssid}.xml"
    reload_command = "sudo systemctl restart wicked"
    install_path = f"/etc/wicked/ifcfg-{ssid}"

    try:
        install_certs_and_keys(extracted_data, config_file, install_path, extra_dirs, False)
        print(f"[✓] Wicked config installed to {config_path}")
    except Exception as e:
        print(f"[!] Failed to install Wicked config: {e}")

def cleanup_tmp(args):
    if not args.noclean:
        print("[*] Cleaning up temporary directory /tmp/aqc...")
        shutil.rmtree("/tmp/aqc", ignore_errors=True)
    else:
        print("[!] --noclean specified, leaving /tmp/aqc intact.")

