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
#from pyasn1.codec.der.decoder import decode as decoder
from pyasn1.codec.der.decoder import decode as asn1_decode

def post_device_metadata(config_values, BASE_URL, USER_AGENT, mac_wifi, mac_eth="CA:FE:CO:FF:EE:99"):
    print("[*] Creating and posting device metadata payload...")

    otp = config_values.get("root", {}).get("global.otp")
    est_url = config_values.get("root", {}).get("global.mdps_url")

    if not otp or not est_url:
        print("[!] Missing OTP or EST server URL in config.")
        return None

    timestamp = int(time.time())
    payload = {
        "device_type": "Ubuntu",
        "id": 1,
        "network_interfaces": [
            {"interface_type": "Wireless", "mac_address": mac_wifi},
            {"interface_type": "Wired", "mac_address": mac_eth}
        ],
        "otp": otp,
        "timestamp": timestamp
    }

    payload_path = "/tmp/aqc/payload1_send.json"
    response_path = "/tmp/aqc/payload1.plist"

    os.makedirs("/tmp/aqc", exist_ok=True)
    with open(payload_path, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"[✓] Payload written to {payload_path}")

    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json"
    })

    try:
        response = session.post(
            url=f"{BASE_URL}/onboard/mdps_qc_enroll.php",
            json=payload,
            timeout=15
        )

        with open(response_path, "wb") as f:
            f.write(response.content)

        print(f"[✓] Response saved to {response_path}")
        return response

    except requests.RequestException as e:
        print(f"[!] Request to EST metadata endpoint failed: {e}")
        return None

def fetch_and_decode_cacerts(config_values, BASE_URL, USER_AGENT):
    print("[*] Fetching CA certificates from EST server...")

    est_url = config_values.get("root", {}).get("global.mdps_url")
    otp = config_values.get("root", {}).get("global.otp")

    if not est_url or not otp:
        print("[!] Missing EST URL or OTP.")
        return False

    cacerts_url = f"{BASE_URL}/.well-known/est/qc:{otp}/cacerts"
    base64_path = "/tmp/aqc/ca_root.b64"
    binary_path = "/tmp/aqc/ca_root.bin"
    log_path = "/tmp/aqc/curl_cacerts.log"

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    try:
        response = session.get(cacerts_url, timeout=10)
        response.raise_for_status()
        with open(base64_path, "wb") as f:
            f.write(response.content)
        print(f"[✓] CA certs base64 saved to {base64_path}")
    except requests.RequestException as e:
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

def convert_pkcs7_der_to_pem_pythonic(der_path="/tmp/aqc/ca_root.bin", pem_path="/tmp/aqc/ca_root.pem"):
    print("[*] Converting ca_root.bin to PEM using cryptography...")
    try:
        with open(der_path, "rb") as f:
            der_data = f.read()

        certs = load_der_pkcs7_certificates(der_data)

        with open(pem_path, "wb") as f:
            for cert in certs:
                f.write(cert.public_bytes(Encoding.PEM))

        print(f"[✓] Certificates written to {pem_path}")
        return True
    except Exception as e:
        print(f"[!] Failed to convert PKCS7 DER to PEM: {e}")
        return False

def extract_credentials_from_plist(extracted_data, plist_path="/tmp/aqc/payload1.plist"):
    print("[*] Extracting credentials and SSID from payload1.plist...")
    try:
        with open(plist_path, "rb") as f:
            plist_data = plistlib.load(f)

        for item in plist_data.get("PayloadContent", []):
            # Extract EAP credentials
            eap_config = item.get("EAPClientConfiguration")
            if eap_config:
                extracted_data["username"] = eap_config.get("UserName")
                extracted_data["password"] = eap_config.get("UserPassword")

            # Extract SSID
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

        #decoded, _ = decoder.decode(data)
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

def fetch_and_parse_csrattrs(extracted_data, config_values, BASE_URL, USER_AGENT):
    print("[*] Fetching CSR attributes from EST server...")

    est_url = config_values.get("root", {}).get("global.mdps_url")
    otp = config_values.get("root", {}).get("global.otp")

    if not est_url or not otp:
        print("[!] Missing EST URL or OTP for CSR attributes.")
        return False

    csrattr_url = f"{BASE_URL}/.well-known/est/qc:{otp}/csrattrs"
    b64_path = "/tmp/aqc/ca_csrattr.b64"
    bin_path = "/tmp/aqc/ca_csrattr.bin"
    txt_path = "/tmp/aqc/ca_csrattr.txt"

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    try:
        response = session.get(csrattr_url, timeout=10)
        response.raise_for_status()
        with open(b64_path, "wb") as f:
            f.write(response.content)
        print(f"[✓] CSR attributes base64 saved to {b64_path}")
    except requests.RequestException as e:
        print(f"[!] ERROR: fetching csrattrs failed: {e}")
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

def generate_private_key_if_missing(extracted_data, key_path="/tmp/aqc/private_key.pem", debug=False):

    if not os.path.exists(key_path):
        print("[*] Creating private key...")
        try:
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, 4096)
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
        print("[*] Generating new RSA private key (4096-bit)...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )

        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print(f"[✓] Private key saved to {key_path}")
    else:
        print("[*] Private key already exists")

    # Use OpenSSL to generate CSR from key and config
    csr_config_path = "/tmp/aqc/csr_config.cnf"
    with open(csr_config_path, "w") as f:
        f.write("""[ req ]
default_bits       = 4096
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

def post_csr_request(config_values, BASE_URL, USER_AGENT, reenroll=False):
    print("[*] Posting CSR to EST server...")
    otp = config_values.get("root", {}).get("global.otp")
    est_url = config_values.get("root", {}).get("global.mdps_url")

    if not est_url or not otp:
        print("[!] Missing EST URL or OTP for CSR post.")
        return False

    endpoint = "simplereenroll" if reenroll else "simpleenroll"
    url = f"{BASE_URL}/.well-known/est/qc:{otp}/{endpoint}"

    csr_file = "/tmp/aqc/csr_mydevice_fix.csr"
    reply_file = "/tmp/aqc/csr_post_reply.b64"

    try:
        with open(csr_file, "rb") as f:
            csr_data = f.read()

        response = requests.post(
            url,
            headers={"Content-Type": "application/csrattrs", "User-Agent": USER_AGENT},
            data=csr_data
        )
        response.raise_for_status()

        with open(reply_file, "wb") as f:
            f.write(response.content)
        print(f"[✓] CSR reply saved to {reply_file}")
        return True
    except requests.RequestException as e:
        print(f"[!] Failed to POST CSR: {e}")
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

