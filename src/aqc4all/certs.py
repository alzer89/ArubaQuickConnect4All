import os
import plistlib
import base64
import subprocess
from pathlib import Path
import time
import json
import requests
import sys
from OpenSSL import crypto
import textwrap
from pyasn1.codec.der.decoder import decode as asn1_decode
from pyasn1.type import univ

key_bits = 4096

def post_device_metadata(config_values, BASE_URL, USER_AGENT, mac_wifi,
                         mac_eth="CA:FE:CO:FF:EE:99"):
    print("[*] Creating and posting device metadata payload...")

    otp = config_values.get("root", {}).get("global.otp")
    est_url = config_values.get("root", {}).get("global.mdps_url")

    if not otp or not est_url:
        print("[!] Missing OTP or EST server URL in config.")
        return None

    # The successful curl request uses milliseconds.
    timestamp = int(time.time() * 1000)

    payload = {
        "device_type": "Ubuntu",
        "id": 1,
        "network_interfaces": [
            {
                "interface_type": "Wireless",
                "mac_address": mac_wifi
            },
            {
                "interface_type": "Wired",
                "mac_address": mac_eth
            }
        ],
        "otp": otp,
        "timestamp": timestamp
    }

    payload_path = "/tmp/aqc/payload1_send.json"
    response_path = "/tmp/aqc/payload1.plist"

    os.makedirs("/tmp/aqc", exist_ok=True)

    payload_json = json.dumps(payload, indent=4)

    with open(payload_path, "w") as f:
        f.write(payload_json)

    url = f"{BASE_URL}onboard/mdps_qc_enroll.php"

    cmd = [
        "curl",
        "-s",
        "-S",
        "-k",
        "--compressed",
        "-X", "POST",
        url,

        "-H", f"Content-Type: application/json",
        "-H", "Connection: Keep-Alive",
        "-H", "Accept-Language: en,*",
        "-H", f"User-Agent: {USER_AGENT}",
        "-H", "Host: onboard-portal.it.unsw.edu.au",

        "-d", payload_json,
        "-o", response_path,
    ]

    print("[i] POST:", url)
    print("[i] Payload:", payload_json)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )

        if result.stderr:
            print("[curl]", result.stderr.strip())

        if os.path.exists(response_path) and os.path.getsize(response_path) > 0:
            print(f"[✓] Response saved to {response_path}")
            return True

        print("[!] Server returned an empty response.")
        return None

    except subprocess.CalledProcessError as e:
        print(f"[!] Curl request to POST device metadata endpoint failed: {e.stderr}")
        return None


def fetch_and_decode_cacerts(config_values, BASE_URL, USER_AGENT):
    print("[*] Fetching CA certificates from EST server...")

    est_url = config_values.get("root", {}).get("global.mdps_url")
    otp = config_values.get("root", {}).get("global.otp")

    if not est_url or not otp:
        print("[!] Missing EST URL or OTP.")
        return False

    cacerts_url = f"{BASE_URL}.well-known/est/qc:{otp}/cacerts"
    base64_path = "/tmp/aqc/ca_root.b64"
    binary_path = "/tmp/aqc/ca_root.bin"
    log_path = "/tmp/aqc/curl_cacerts.log"

    cmd = [
        "curl", "--http1.1", "-s", "-S", "-k", "-X", "GET", cacerts_url,
        "-H", f"User-Agent: {USER_AGENT}",
        "-o", base64_path
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if not os.path.exists(base64_path) or os.path.getsize(base64_path) == 0:
            raise Exception("Empty response from server")
        print(f"[✓] CA certs base64 saved to {base64_path}")
    except Exception as e:
        with open(log_path, "w") as log:
            log.write(str(e))
        print(f"[!] ERROR: fetching cacerts failed. Details in {log_path}")
        return False

    try:
        subprocess.run(
            ["openssl", "base64", "-d", "-in", base64_path, "-out", binary_path],
            check=True
        )
        print(f"[✓] Decoded CA certs to {binary_path}")
        return True
    except subprocess.CalledProcessError:
        print("[!] Failed to decode base64 CA certs.")
        return False

def fetch_and_parse_csrattrs(extracted_data, config_values, BASE_URL, USER_AGENT):
    print("[*] Fetching CSR attributes from EST server...")

    est_url = config_values.get("root", {}).get("global.mdps_url")
    otp = config_values.get("root", {}).get("global.otp")

    if not est_url or not otp:
        print("[!] Missing EST URL or OTP for CSR attributes.")
        return False

    csrattr_url = f"{BASE_URL}.well-known/est/qc:{otp}/csrattrs"
    b64_path = "/tmp/aqc/ca_csrattr.b64"
    bin_path = "/tmp/aqc/ca_csrattr.bin"
    txt_path = "/tmp/aqc/ca_csrattr.txt"

    cmd = [
        "curl", "--http1.1", "-s", "-S", "-k", "-X", "GET", csrattr_url,
        "-H", f"User-Agent: {USER_AGENT}",
        "-o", b64_path
    ]

    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        if not os.path.exists(b64_path) or os.path.getsize(b64_path) == 0:
            print("[!] ERROR: fetching csrattrs returned empty response.")
            return False
        print(f"[✓] CSR attributes base64 saved to {b64_path}")
    except subprocess.CalledProcessError as e:
        print(f"[!] ERROR: fetching csrattrs failed: {e.stderr}")
        return False

    try:
        with open(b64_path, "rb") as f:
            decoded = base64.b64decode(f.read())
        with open(bin_path, "wb") as f:
            f.write(decoded)
        print(f"[✓] CSR attributes binary saved to {bin_path}")
    except Exception as e:
        print(f"[!] Failed to decode CSR attributes: {e}")
        return False
    return parse_csrattrs_der(extracted_data, bin_path, txt_path)

def post_csr_request(config_values, BASE_URL, USER_AGENT, reenroll=False):
    print("[*] Posting CSR to EST server using curl...")

    otp = config_values.get("root", {}).get("global.otp")
    est_url = config_values.get("root", {}).get("global.mdps_url")

    if not est_url or not otp:
        print("[!] Missing EST URL or OTP for CSR post.")
        return False

    endpoint = "simplereenroll" if reenroll else "simpleenroll"
    url = f"{BASE_URL}.well-known/est/qc:{otp}/{endpoint}"

    csr_file = "/tmp/aqc/csr_mydevice_fix.csr"
    reply_file = "/tmp/aqc/csr_post_reply.b64"

    if not os.path.exists(csr_file):
        print(f"[!] Cleaned CSR file not found at {csr_file}")
        return False

    cmd = [
        "curl",
        "--http1.1",
        "-s",
        "-S",
        "-k",
        "--compressed",
        "-X", "POST",
        url,

        "-H", "Content-Type: text/plain",
        "-H", "Connection: Keep-Alive",
        "-H", "Accept-Language: en,*",
        "-H", f"User-Agent: {USER_AGENT}",
        "-H", "Host: onboard-portal.it.unsw.edu.au",

        "--data-binary", f"@{csr_file}",
        "-o", reply_file,
    ]

    print("[i] POST:", url)
    print("[i] CSR:", csr_file)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )

        if result.stderr:
            print("[curl]", result.stderr.strip())

        if os.path.exists(reply_file) and os.path.getsize(reply_file) > 0:
            print(f"[✓] CSR reply saved to {reply_file}")
            return True

        print("[!] Server returned an empty response for CSR enrollment.")
        return False

    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to POST CSR via curl: {e.stderr}")
        return False

def load_existing_private_key(extracted_data, key_path="/tmp/aqc/private_key.pem"):
    print("[*] Checking for existing private key for renewal...")
    os.makedirs(os.path.expanduser("~/.config/aqc4all"), exist_ok=True)
    persist_path = os.path.expanduser("~/.config/aqc4all/private_key.pem")

    if os.path.exists(persist_path) and not os.path.exists(key_path):
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        with open(persist_path, "rb") as src, open(key_path, "wb") as dst:
            dst.write(src.read())

    if os.path.exists(key_path):
        print(f"[✓] Using existing private key found at {key_path}")
        extracted_data['priv_key'] = key_path
        return True

    print("[!] No existing private key found. A new one will be generated.")
    return False

def extract_credentials_from_plist(extracted_data, plist_path="/tmp/aqc/payload1.plist"):
    print("[*] Extracting credentials and SSID from payload1.plist...")
    try:
        with open(plist_path, "rb") as f:
            plist_data = plistlib.load(f)

        for item in plist_data.get("PayloadContent", []):
            eap_config = item.get("EAPClientConfiguration")
            if eap_config:
                extracted_data["username"] = eap_config.get("UserName")
                extracted_data["password"] = eap_config.get("UserPassword")

            if item.get("PayloadType") == "com.apple.wifi.managed":
                ssid = item.get("SSID_STR")
                if ssid:
                    if ssid == 'eduroam-unsw':
                        extracted_data['ssid'] = 'eduroam'
                    else:
                        extracted_data["ssid"] = ssid

        if extracted_data.get("username") and extracted_data.get("password"):
            print("[✓] Extracted username and password from payload1.plist")
        if extracted_data.get("ssid"):
            print(f"[✓] Extracted SSID: {extracted_data['ssid']}")
            return extracted_data

    except Exception as e:
        print(f"[!] Failed to extract credentials: {e}")

def extract_certs_from_plist(extracted_data, plist_path="/tmp/aqc/payload1.plist"):
    print("[*] Extracting CA certificates from plist...")
    try:
        with open(plist_path, "rb") as f:
            data = plistlib.load(f)

        for entry in data.get("PayloadContent", []):
            if entry.get("PayloadType") == "com.apple.security.pkcs1":
                display_name = entry.get("PayloadDisplayName", "")
                cert_data = entry.get("PayloadContent")

                if not isinstance(cert_data, bytes):
                    print("[!] PayloadContent is not in bytes format. Skipping.")
                    continue

                if "oot" in display_name:
                    filename = "ca_root.pem"
                else:
                    filename = f"{display_name.replace(' ', '_')}.pem"

                output_path = f"/tmp/aqc/{filename}"
                pem_lines = base64.encodebytes(cert_data).decode('ascii')
                pem_body = ''.join(pem_lines.splitlines())

                with open(output_path, "w") as cert_file:
                    cert_file.write("-----BEGIN CERTIFICATE-----\n")
                    cert_file.write('\n'.join(textwrap.wrap(pem_body, 64)))
                    cert_file.write("\n-----END CERTIFICATE-----\n")

                print(f"[✓] Extracted cert to {output_path}")
                extracted_data['root_cert'] = output_path
        return True

    except Exception as e:
        print(f"[!] Error extracting certs from plist: {e}")
        return False

def parse_csrattrs_der(extracted_data, bin_path="/tmp/aqc/ca_csrattr.bin", txt_path="/tmp/aqc/ca_csrattr.txt"):
    print("[*] Parsing ASN.1 CSR attributes using pyasn1...")

    try:
        with open(bin_path, "rb") as f:
            data = f.read()

        decoded, _ = asn1_decode(data)

        def walk(asn1_obj, indent=0):
            lines = []
            if isinstance(asn1_obj, univ.SequenceOf) or isinstance(asn1_obj, univ.SetOf):
                for i, item in enumerate(asn1_obj):
                    lines.extend(walk(item, indent + 2))
            elif isinstance(asn1_obj, univ.Sequence):
                for field in asn1_obj:
                    lines.extend(walk(field, indent + 2))
            else:
                lines.append(" " * indent + str(asn1_obj))
            return lines

        with open(txt_path, "w") as f:
            f.write("\n".join(walk(decoded)))
        print(f"[✓] Parsed CSR attributes written to {txt_path}")
        return True

    except Exception as e:
        print(f"[!] Failed to parse CSR attributes ASN.1: {e}")
        return False

def generate_private_key_if_missing(extracted_data, key_path="/tmp/aqc/private_key.pem", debug=False):
    if not os.path.exists(key_path):
        print("[*] Creating private key...")
        try:
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, key_bits)
            with open(key_path, "wb") as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
            print(f"[✓] Private key saved to {key_path}")
            extracted_data['priv_key'] = key_path
        except Exception as e:
            print(f"[!] ERROR: failed to generate private key: {e}")
            sys.exit(1)
    else:
        print("[*] Private key already exists")

    print(f"[i] Private key info: {key_path}")
    os.chmod(key_path, 0o600)

    if debug:
        print("----- private_key.pem -----")
        try:
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(key_path, "rb").read())
            modulus = key.to_cryptography_key().private_numbers().public_numbers.n
            print("Modulus:", hex(modulus))
        except Exception as e:
            print(f"[!] Failed to print modulus: {e}")
        print("---------------------------")

def generate_csr_from_key():
    print("[*] Creating CSR from private key...")
    key_path = "/tmp/aqc/private_key.pem"
    csr_path = "/tmp/aqc/csr_mydevice.csr"
    csr_fixed_path = "/tmp/aqc/csr_mydevice_fix.csr"

    os.makedirs("/tmp/aqc", exist_ok=True)

    if not os.path.exists(key_path):
        print("[*] Private key missing. Please generate it first.")
        return False

    csr_config_path = "/tmp/aqc/csr_config.cnf"
    with open(csr_config_path, "w") as f:
        f.write(f"""[ req ]
default_bits       = {key_bits}
distinguished_name = req_distinguished_name
prompt             = no

[ req_distinguished_name ]
CN = Request Linux Certificate
""")
    print(f"[✓] CSR config written to {csr_config_path}")

    try:
        subprocess.run([
            "openssl", "req",
            "-sha256",
            "-new", "-key", key_path,
            "-out", csr_path,
            "-config", csr_config_path
        ], check=True)
        print(f"[✓] CSR generated at {csr_path}")
    except subprocess.CalledProcessError as e:
        print(f"[!] OpenSSL CSR generation failed: {e}")
        return False

    try:
        with open(csr_path, "r") as f:
            lines = f.readlines()
        clean_lines = [line for line in lines if not line.startswith("---")]
        with open(csr_fixed_path, "w") as f:
            f.write("\n" + "".join(clean_lines) + "\n")
        print(f"[✓] Cleaned CSR saved to {csr_fixed_path}")
        return True
    except Exception as e:
        print(f"[!] Failed to clean CSR: {e}")
        return False

def process_csr_response(extracted_data):
    print("[*] Processing CSR response and converting to PEM...")
    b64_input = "/tmp/aqc/csr_post_reply.b64"
    pkcs7_output = "/tmp/aqc/client.pk"
    pem_output = "/tmp/aqc/client.pem"

    try:
        with open(b64_input, "rb") as f:
            b64_data = f.read()

        with open(pkcs7_output, "wb") as f:
            f.write(b"-----BEGIN PKCS7-----\n")
            f.write(b64_data)
            f.write(b"-----END PKCS7-----\n")
        print(f"[✓] PKCS7 written to {pkcs7_output}")

        subprocess.run([
            "openssl", "pkcs7", "-in", pkcs7_output, "-print_certs", "-out", pem_output
        ], check=True)
        print(f"[✓] PEM certificate saved to {pem_output}")

        subprocess.run([
            "openssl", "x509", "-in", pem_output, "-text", "-noout"
        ], check=True)

        extracted_data["client_cert"] = pem_output
        return True
    except Exception as e:
        print(f"[!] Failed to process CSR response: {e}")
        return False

def generate_p12_bundle(extracted_data, output_dir="/tmp/aqc"):
    """
    Bundles client.pem and private_key.pem into a .p12 (PKCS#12) file
    required by Android and manual mobile imports.
    """
    ssid = extracted_data.get('ssid', 'eduroam')
    p12_path = os.path.join(output_dir, f"{ssid}_client.p12")
    client_cert = os.path.join(output_dir, "client.pem")
    private_key = os.path.join(output_dir, "private_key.pem")
    ca_root = os.path.join(output_dir, "ca_root.pem")
    password = extracted_data.get('password', 'changeme')

    if not os.path.exists(client_cert) or not os.path.exists(private_key):
        print("[!] Client cert or private key missing, cannot generate .p12 bundle.")
        return None

    # OpenSSL command to bundle cert, key, and optional CA chain into a .p12 file
    cmd = [
        "openssl", "pkcs12", "-export",
        "-out", p12_path,
        "-inkey", private_key,
        "-in", client_cert,
        "-certfile", ca_root,
        "-password", f"pass:{password}"
    ]

    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"[✓] Android PKCS#12 bundle written to {p12_path}")
        return p12_path
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to generate .p12 file: {e.stderr.decode().strip()}")
        return None
