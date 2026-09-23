import uuid
import binascii
import uuid
import os
import base64
import json

def generate_networkmanager_profile(created_configs, extracted_data, cert_path="/tmp/aqc/client.pem", key_path="/tmp/aqc/private_key.pem"):
    nm_path = f"/tmp/aqc/{extracted_data['ssid']}.nmconnection"
    with open(nm_path, "w") as f:
        f.write(f"""[connection]
id={extracted_data['ssid']}
uuid={uuid.uuid4()}
type=wifi

[wifi]
mode=infrastructure
ssid={extracted_data['ssid']}

[wifi-security]
key-mgmt=wpa-eap

[802-1x]
eap=tls
identity={extracted_data['username']}
ca-cert={extracted_data['root_cert']}
client-cert={extracted_data['client_cert']}
private-key={extracted_data['priv_key']}
private-key-password-flags=0
private-key-password={extracted_data['password']}
phase2-auth=mschapv2

[ipv4]
method=auto

[ipv6]
method=auto
""")
    print(f"[✓] NetworkManager profile written to {nm_path}")
    created_configs.append(f"{nm_path}")

def generate_netplan_yaml(created_configs, extracted_data, cert_path="/tmp/aqc/client.pem", key_path="/tmp/aqc/private_key.pem"):
    con_uuid = uuid.uuid4()
    netplan_path = f"/tmp/aqc/{extracted_data['ssid']}.yaml"
    with open(netplan_path, "w") as f:
        f.write(f"""network:
  version: 2
  wifis:
    NM-{con_uuid}:
      renderer: NetworkManager
      match: {{}}
      dhcp4: true
      dhcp6: true
      access-points:
        "{extracted_data['ssid']}":
          auth:
            key-management: "eap"
            method: "tls"
            identity: "{extracted_data['username']}"
            ca-certificate: "{extracted_data['root_cert']}"
            client-certificate: "{cert_path}"
            client-key: "{key_path}"
            client-key-password: "{extracted_data['password']}"
            phase2-auth: "mschapv2"
            password: "{extracted_data['password']}"
          networkmanager:
            uuid: "{con_uuid}"
            name: "{extracted_data['ssid']}"
            passthrough:
              connection.autoconnect: "false"
              ipv6.addr-gen-mode: "default"
              ipv6.ip6-privacy: "-1"
              proxy._: ""
      networkmanager:
        uuid: "{con_uuid}"
        name: "{extracted_data['ssid']}"
""")
    print(f"[✓] NetPlan YAML written to {netplan_path}")
    created_configs.append(f"{netplan_path}")

def generate_wpa_supplicant_config(created_configs, extracted_data, cert_path="/tmp/aqc/client.pem", key_path="/tmp/aqc/private_key.pem"):
    wpa_path = f"/tmp/aqc/wpa_supplicant_{extracted_data['ssid']}.conf"
    with open(wpa_path, "w") as f:
        f.write(f"""network={{
    ssid="{extracted_data['ssid']}"
    key_mgmt=WPA-EAP
    eap=TLS
    identity="{extracted_data['username']}"
    ca_cert="{extracted_data['root_cert']}"
    client_cert="{extracted_data['client_cert']}"
    private_key="{extracted_data['priv_key']}"
    phase2="auth=MSCHAPV2"
    password="{extracted_data['password']}"
    priority=1
}}""")
    print(f"[✓] wpa_supplicant config written to {wpa_path}")
    created_configs.append(f"{wpa_path}")

def generate_systemd_networkd_config(created_configs, extracted_data, cert_path="/tmp/aqc/client.pem", key_path="/tmp/aqc/private_key.pem"):
    netdev_path = "/tmp/aqc/25-wlan.netdev"
    network_path = "/tmp/aqc/25-wlan.network"
    with open(netdev_path, "w") as f:
        f.write("[NetDev]\nName=wlan0\nKind=wlan\n")
    with open(network_path, "w") as f:
        f.write(f"""[Match]
Name=wlan0

[Network]
DHCP=yes

[Wireless]
SSID={extracted_data['ssid']}
KeyMgmt=wpa-eap
EAP=tls
Identity={extracted_data['username']}
ClientCertificate={extracted_data['client_cert']}
PrivateKey={extracted_data['priv_key']}
CAFile={extracted_data['root_cert']}
""")
    print(f"[✓] systemd-networkd config written to {netdev_path} and {network_path}")
    created_configs.append(f"{netdev_path}")
    created_configs.append(f"{network_path}")

def generate_netifrc_config(created_configs, extracted_data, cert_path="/tmp/aqc/client.pem", key_path="/tmp/aqc/private_key.pem"):
    net_path = "/tmp/aqc/conf.d_net"
    with open(net_path, "w") as f:
        f.write(f"""modules_wlan0="wpa_supplicant"
config_wlan0="dhcp"
wpa_supplicant_wlan0="-Dnl80211 -c/etc/wpa_supplicant/wpa_supplicant_{extracted_data['ssid']}.conf"
""")
    print(f"[✓] netifrc config written to {net_path}")
    created_configs.append(f"{net_path}")

def _pem_to_base64_der(pem_path):
    """Helper to convert a PEM certificate file into raw base64 DER for mobileconfig <data> tags."""
    if not os.path.exists(pem_path):
        return ""
    with open(pem_path, "r") as f:
        content = f.read()

    lines = []
    in_cert = False
    for line in content.splitlines():
        if "-----BEGIN" in line:
            in_cert = True
            continue
        if "-----END" in line:
            in_cert = False
            continue
        if in_cert:
            lines.append(line.strip())
    return "".join(lines)

def generate_chromeos_onc_config(created_configs, extracted_data)
    cert_path = extracted_data['client_cert']
    key_path = extracted_data['priv_key']
    ca_path = extracted_data['root_cert']
    ssid = extracted_data['ssid']
    safe_ssid = ssid.lower().replace(' ', '_')
    onc_path = f"/tmp/aqc/{safe_ssid}.onc"

    try:
        with open(ca_path, "r") as f:
            ca_pem = f.read()
        with open(cert_path, "r") as f:
            client_cert_pem = f.read()
        with open(key_path, "r") as f:
            private_key_pem = f.read()
    except FileNotFoundError as e:
        print(f"[!] Warning: Missing certificate file for ONC generation: {e}")
        ca_pem, client_cert_pem, private_key_pem = "", "", ""

    ca_guid = f"cert-ca-{safe_ssid}"
    client_guid = f"cert-client-{safe_ssid}"

    onc_data = {
        "Type": "UnencryptedConfiguration",
        "NetworkConfigurations": [
            {
                "GUID": f"wifi-eap-tls-{safe_ssid}",
                "Name": ssid,
                "Type": "WiFi",
                "WiFi": {
                    "AutoConnect": True,
                    "SSID": ssid,
                    "Security": "WPA-EAP",
                    "EAP": {
                        "Outer": "EAP-TLS",
                        "Identity": extracted_data['username'],
                        "ClientCertType": "Ref",
                        "ClientCertRef": client_guid,
                        "ServerCARefs": [ca_guid]
                    }
                }
            }
        ],
        "Certificates": [
            {
                "GUID": ca_guid,
                "Type": "Authority",
                "X509": ca_pem
            },
            {
                "GUID": client_guid,
                "Type": "Client",
                "X509": client_cert_pem,
                "PrivateKeyPEM": private_key_pem
            }
        ]
    }

    with open(onc_path, "w", encoding="utf-8") as f:
        json.dump(onc_data, f, indent=4)

    print(f"[✓] ChromeOS ONC config written to {onc_path}")
    created_configs.append(onc_path)

def generate_windows_xml_profile(created_configs, extracted_data):
    cert_path = extracted_data['client_cert']
    key_path = extracted_data['priv_key']
    ssid = extracted_data['ssid']
    # Oh wait, this has to run on WINDOWS.  Better do some stuff to it...
    safe_ssid_name = ssid.lower().replace(' ', '_')
    xml_path = f"/tmp/aqc/{safe_ssid_name}_windows.xml"
    bat_path = f"/tmp/aqc/install_{safe_ssid_name}_windows.bat"

    # Windows XML requires the SSID converted to Hexadecimal format, because, who knows...
    ssid_hex = binascii.hexlify(ssid.encode('utf-8')).decode('utf-8')

    # WLAN XML Profile - The meat and potatoes of Wi-Fi on Windows
    xml_content = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <!-- Yeah, Windows wants the SSID in HEXADEMICAL as well... --->
            <hex>{ssid_hex}</hex>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ess</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <auth>WPA2</auth>
                <encryption>AES</encryption>
                <useOneX>true</useOneX>
            </authEncryption>
            <OneX xmlns="http://www.microsoft.com/networking/onenx/v1">
                <cacheUserData>true</cacheUserData>
                <authMode>user</authMode>
                <EAPConfig>
                    <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                        <Eap>
                            <Type>13</Type>
                            <Authoritative>true</Authoritative>
                            <EapMethod>
                                <Type>13</Type>
                                <VendorId>0</VendorId>
                                <VendorType>0</VendorType>
                                <Authoritative>true</Authoritative>
                            </EapMethod>
                            <!-- Configures EAP-TLS to trust the CA by default and look for client certs automatically, because...Windows... (-_-') -->
                            <Config xmlns:base="http://www.microsoft.com/provisioning/EapBasePropertiesV1">
                                <base:EapTlsProperties>
                                    <base:MaxAuthenticationFailures>1</base:MaxAuthenticationFailures>
                                    <base:AdjustServerName>false</base:AdjustServerName>
                                    <base:DisableUserPromptForServerValidation>true</base:DisableUserPromptForServerValidation>
                                    <base:ServerNames></base:ServerNames>
                                    <base:TrustedRootCAHash></base:TrustedRootCAHash>
                                    <base:ClientCertificateSelection>
                                        <base:AutoSelectCredential>true</base:AutoSelectCredential>
                                    </base:ClientCertificateSelection>
                                    <base:AllowFreshCredentials>false</base:AllowFreshCredentials>
                                </base:EapTlsProperties>
                            </Config>
                        </Eap>
                    </EapHostConfig>
                </EAPConfig>
            </OneX>
        </security>
    </MSM>
</WLANProfile>
"""
    with open(xml_path, "w", encoding="utf-8") as f:
        f.write(xml_content)

    # Nice little batch script for the Windows user to double-click on
    bat_content = f"""@echo off
TITLE Installing Wi-Fi Profile: {ssid}
echo [*] Adding wireless profile for {ssid} into Windows...
netsh wlan add profile filename="{safe_ssid_name}_windows.xml" user=all
echo.
echo [*] Done! You can now select '{ssid} from your available networks.
pause
"""
    with open(bat_path, "w", encoding="utf-8") as f:
        f.write(bat_content)

    print(f"[✓] Windows XML profile written to {xml_path}")
    print(f"[✓] Windows installer batch script written to {bat_path}")

    created_configs.append(xml_path)
    created_configs.append(bat_path)

def generate_openwrt_config(created_configs, extracted_data, cert_path="/etc/certs/client.pem", key_path="/etc/certs/private_key.pem", ca_path="/etc/certs/ca.pem"):
    ssid = extracted_data['ssid']
    safe_ssid = ssid.lower().replace(' ', '_')
    openwrt_path = f"/tmp/aqc/{safe_ssid}_openwrt.include"

    config_content = f"""
# OpenWrt UCI Wireless Configuration Snippet for EAP-TLS
# Useful if you want to make your OpenWRT device a network proxy
# 1. Copy certificates to /etc/certs/ on the router
# 2. Append the block below to /etc/config/wireless
# Note: Requires the full 'wpad' package (apk add wpad | opkg install wpad).
# wpad-mini will not work...

config wifi-iface 'eap_tls_client'
    option device 'radio0'
    option mode 'sta'
    option ssid '{ssid}'
    option network 'wwan'
    option encryption 'wpa2-eap'
    option eap_type 'tls'
    option identity '{extracted_data['username']}'
    option ca_cert '{ca_path}'
    option client_cert '{cert_path}'
    option private_key '{key_path}'
    option private_key_passwd '{extracted_data['password']}'

"""

    with open(openwrt_path, "w", encoding="utf-8") as f:
        f.write(config_content)

    print(f"[✓] OpenWrt configuration snippet written to {openwrt_path}")
    created_configs.append(openwrt_path)

def generate_apple_mobileconfig(created_configs, extracted_data, cert_path="/tmp/aqc/client.pem", key_path="/tmp/aqc/private_key.pem"):
    ssid = extracted_data['ssid']
    mobileconfig_path = f"/tmp/aqc/{ssid}.mobileconfig"

    profile_uuid = str(uuid.uuid4())
    wifi_uuid = str(uuid.uuid4())
    ca_uuid = str(uuid.uuid4())
    cert_uuid = str(uuid.uuid4())

    root_ca_path = extracted_data.get('root_cert', '/tmp/aqc/ca_root.pem')
    ca_cert_base64 = _pem_to_base64_der(root_ca_path)

    # Convert client cert/key or read a combined p12 if available
    # For this fix, we assume extracted_data has a base64 version or we generate/read the p12 bytes
    p12_path = extracted_data.get('p12_path', f"/tmp/aqc/{ssid}_ios_client.p12")
    if os.path.exists(p12_path):
        with open(p12_path, "rb") as pf:
            p12_base64 = base64.b64encode(pf.read()).decode('utf-8')
    else:
        p12_base64 = ""

    with open(mobileconfig_path, "w") as f:
        f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadDisplayName</key>
    <string>{ssid} Wi-Fi (aqc4all)</string>
    <key>PayloadDescription</key>
    <string>Secure EAP-TLS configuration profile for {ssid}</string>
    <key>PayloadIdentifier</key>
    <string>com.aqc4all.utility.{ssid.lower().replace(' ', '')}</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{profile_uuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadContent</key>
    <array>
        <!-- Root CA Certificate Payload -->
        <dict>
            <key>PayloadCertificateFileName</key>
            <string>ca_root.cer</string>
            <key>PayloadContent</key>
            <data>{ca_cert_base64}</data>
            <key>PayloadDisplayName</key>
            <string>Root CA Certificate ({ssid})</string>
            <key>PayloadIdentifier</key>
            <string>com.aqc4all.utility.ca.{ssid.lower().replace(' ', '')}</string>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadUUID</key>
            <string>{ca_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>

        <!-- Client Certificate (PKCS#12) Payload -->
        <dict>
            <key>PayloadContent</key>
            <data>{p12_base64}</data>
            <key>PayloadCertificateFileName</key>
            <string>client_bundle.p12</string>
            <key>PayloadDisplayName</key>
            <string>Client Certificate ({ssid})</string>
            <key>PayloadIdentifier</key>
            <string>com.aqc4all.utility.pkcs12.{ssid.lower().replace(' ', '')}</string>
            <key>PayloadType</key>
            <string>com.apple.security.pkcs12</string>
            <key>PayloadUUID</key>
            <string>{cert_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>Password</key>
            <string>{extracted_data['password']}</string>
        </dict>

        <!-- Managed Wi-Fi Payload -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.wifi.managed</string>
            <key>PayloadIdentifier</key>
            <string>com.aqc4all.utility.wifi.{ssid.lower().replace(' ', '')}</string>
            <key>PayloadUUID</key>
            <string>{wifi_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadDisplayName</key>
            <string>Wi-Fi: {ssid}</string>
            <key>SSID_STR</key>
            <string>{ssid}</string>
            <key>EncryptionType</key>
            <string>WPA2</string>
            <key>AutoJoin</key>
            <true/>
            <key>EAPClientConfiguration</key>
            <dict>
                <key>AcceptEAPTypes</key>
                <array>
                    <integer>13</integer>
                </array>
                <key>PayloadCertificateAnchorUUID</key>
                <array>
                    <string>{ca_uuid}</string>
                </array>
                <key>UserName</key>
                <string>{extracted_data['username']}</string>
                <key>TLSCertificateIsRequired</key>
                <true/>
                <key>PayloadCertificateUUID</key>
                <string>{cert_uuid}</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>
""")
    print(f"[✓] Apple mobileconfig written to {mobileconfig_path}")
    created_configs.append(mobileconfig_path)

def generate_android_wifi_config(created_configs, extracted_data, cert_path="/tmp/aqc/client.pem", key_path="/tmp/aqc/private_key.pem"):
    xml_path = f"/tmp/aqc/{extracted_data['ssid']}_android_instructions.xml"
    with open(xml_path, "w") as f:
        f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<AndroidEnterpriseWiFiConfig>
    <!--
      NOTE: Android requires manual import of certificates due to OS security sandboxing.
      Follow these parameters on your Android device:
    -->
    <SSID>{extracted_data['ssid']}</SSID>
    <SecurityType>WPA2/WPA3-Enterprise</SecurityType>
    <EAPMethod>TLS (Certificate)</EAPMethod>
    <Phase2Authentication>None or MSCHAPv2</Phase2Authentication>
    <Identity>{extracted_data['username']}</Identity>
    <CACertificateFile>ca_root.pem</CACertificateFile>
    <ClientCertificateFile>client.pem</ClientCertificateFile>
    <PrivateKeyFile>private_key.pem</PrivateKeyFile>
    <Password>{extracted_data['password']}</Password>
</AndroidEnterpriseWiFiConfig>
""")
    print(f"[✓] Android configuration guide written to {xml_path}")
    created_configs.append(xml_path)

def generate_netctl_config(created_configs, extracted_data, cert_path="/tmp/aqc/client.pem", key_path="/tmp/aqc/private_key.pem"):
    netctl_path = f"/tmp/aqc/netctl_{extracted_data['ssid']}"
    with open(netctl_path, "w") as f:
        f.write(f"""Description='{extracted_data['ssid']}'
Interface=wlan0
Connection=wireless
Security=wpa-configsection
IP=dhcp

WPAConfigSection=(
    'ssid="{extracted_data['ssid']}"'
    'key_mgmt=WPA-EAP'
    'eap=TLS'
    'identity="{extracted_data['username']}"'
    'ca_cert="{extracted_data['root_cert']}"'
    'client_cert="{extracted_data['client_cert']}"'
    'private_key="{extracted_data['priv_key']}"'
    'password="{extracted_data['password']}"'
    'phase2="auth=MSCHAPV2"'
)
""")
    print(f"[✓] netctl config written to {netctl_path}")
    created_configs.append(f"{netctl_path}")

def generate_connman_settings(created_configs, extracted_data, cert_path="/tmp/aqc/client.pem", key_path="/tmp/aqc/private_key.pem"):
    connman_path = f"/tmp/aqc/{extracted_data['ssid']}.config"
    with open(connman_path, "w") as f:
        f.write(f"""[service_{extracted_data['ssid']}]
Type=wifi
Name={extracted_data['ssid']}
EAP=TLS
Phase2Auth=MSCHAPV2
CACertFile={extracted_data['root_cert']}
ClientCertFile={extracted_data['client_cert']}
PrivateKeyFile={extracted_data['priv_key']}
PrivateKeyPassphrase={extracted_data['password']}
Identity={extracted_data['username']}
IPv4=dhcp
IPv6=off
""")
    print(f"[✓] connman config written to {connman_path}")
    created_configs.append(f"{connman_path}")

def generate_wicked_config(created_configs, extracted_data, cert_path="/tmp/aqc/client.pem", key_path="/tmp/aqc/private_key.pem"):
    wicked_path = f"/tmp/aqc/wicked_{extracted_data['ssid']}.xml"
    with open(wicked_path, "w") as f:
        f.write(f"""<network>
  <service name="{extracted_data['ssid']}">
    <interface name="wlan0">
      <wireless>
        <essid>{extracted_data['ssid']}</essid>
        <eap>
          <method>TLS</method>
          <ca-cert>{extracted_data['root_cert']}</ca-cert>
          <client-cert>{extracted_data['client_cert']}</client-cert>
          <private-key>{extracted_data['priv_key']}</private-key>
          <identity>{extracted_data['username']}</identity>
          <password>{extracted_data['password']}</password>
        </eap>
      </wireless>
      <ipv4>
        <method>auto</method>
      </ipv4>
    </interface>
  </service>
</network>
""")
    print(f"[✓] wicked config written to {wicked_path}")
    created_configs.append(f"{wicked_path}")

def generate_iwd_settings(created_configs, extracted_data, cert_path="/tmp/aqc/client.pem", key_path="/tmp/aqc/private_key.pem"):
    iwd_path = f"/tmp/aqc/{extracted_data['ssid']}.8021x"
    with open(iwd_path, "w") as f:
        f.write(f"""[Security]
EAP-Method=TLS
EAP-TLS-CACert={extracted_data['root_cert']}
EAP-Identity={extracted_data['username']}
EAP-TLS-ClientCert={extracted_data['client_cert']}
EAP-TLS-ClientKey={extracted_data['priv_key']}

[Settings]
AutoConnect=true
""")
    print(f"[✓] iwd config written to {iwd_path}")
    created_configs.append(f"{iwd_path}")
