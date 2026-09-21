import uuid

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

import uuid
import os
import base64

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

def generate_apple_mobileconfig(created_configs, extracted_data, cert_path="/tmp/aqc/client.pem", key_path="/tmp/aqc/private_key.pem"):
    ssid = extracted_data['ssid']
    mobileconfig_path = f"/tmp/aqc/{ssid}.mobileconfig"

    profile_uuid = str(uuid.uuid4())
    wifi_uuid = str(uuid.uuid4())
    ca_uuid = str(uuid.uuid4())

    root_ca_path = extracted_data.get('root_cert', '/tmp/aqc/ca_root.pem')
    ca_cert_base64 = _pem_to_base64_der(root_ca_path)

    with open(mobileconfig_path, "w") as f:
        f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadDisplayName</key>
    <string>{ssid} Enterprise Wi-Fi</string>
    <key>PayloadDescription</key>
    <string>Secure EAP-TLS configuration profile for {ssid}</string>
    <key>PayloadIdentifier</key>
    <string>com.aruba.quickconnect.{ssid.lower().replace(' ', '')}</string>
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
        <!-- Root CA Certificate Payload for Server Trust Pinning -->
        <dict>
            <key>PayloadCertificateFileName</key>
            <string>ca_root.cer</string>
            <key>PayloadContent</key>
            <data>{ca_cert_base64}</data>
            <key>PayloadDisplayName</key>
            <string>Root CA Certificate ({ssid})</string>
            <key>PayloadIdentifier</key>
            <string>com.aruba.quickconnect.ca.{ssid.lower().replace(' ', '')}</string>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadUUID</key>
            <string>{ca_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>

        <!-- Managed Wi-Fi Payload -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.wifi.managed</string>
            <key>PayloadIdentifier</key>
            <string>com.aruba.quickconnect.wifi.{ssid.lower().replace(' ', '')}</string>
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
