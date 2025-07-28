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
        f.write("""[Match]
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
        f.write("""modules_wlan0="wpa_supplicant"
config_wlan0="dhcp"
wpa_supplicant_wlan0="-Dnl80211 -c/etc/wpa_supplicant/wpa_supplicant_{extracted_data['ssid']}.conf"
""")
    print(f"[✓] netifrc config written to {net_path}")
    created_configs.append(f"{net_path}")

def generate_apple_mobileconfig(created_configs, extracted_data, cert_path="/tmp/aqc/client.pem", key_path="/tmp/aqc/private_key.pem"):
    ssid = extracted_data['ssid']
    mobileconfig_path = f"/tmp/aqc/{ssid}.mobileconfig"
    payload_uuid = str(uuid.uuid4())
    with open(mobileconfig_path, "w") as f:
        f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.wifi.managed</string>
      <key>PayloadIdentifier</key>
      <string>quickconnect.aruba.wifi.{ssid}</string>
      <key>SSID_STR</key>
      <string>{extracted_data['ssid']}</string>
      <key>EncryptionType</key>
      <string>WPA2</string>
      <key>EAPClientConfiguration</key>
      <dict>
        <key>EAPFASTProvisionPAC</key>
        <false/>
        <key>AcceptEAPTypes</key>
        <array><integer>13</integer></array>
        <key>PayloadCertificateAnchorUUID</key>
        <array><string>{payload_uuid}</string></array>
      </dict>
    </dict>
  </array>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
""")
    print(f"[✓] Apple mobileconfig written to {mobileconfig_path}")
    created_configs.append(f"{mobileconfig_path}")

def generate_android_wifi_config(created_configs, extracted_data, cert_path="/tmp/aqc/client.pem", key_path="/tmp/aqc/private_key.pem"):
    xml_path = f"/tmp/aqc/{extracted_data['ssid']}_android.xml"
    with open(xml_path, "w") as f:
        f.write("""<?xml version="1.0" encoding="UTF-8"?>
<WifiConfig>
    <SSID>{extracted_data['ssid']}</SSID>
    <SecurityType>WPA2</SecurityType>
    <EAPMethod>TLS</EAPMethod>
    <Identity>{extracted_data['username']}</Identity>
    <ClientCertificate>{extracted_data['client_cert']}</ClientCertificate>
    <PrivateKey>{extracted_data['priv_key']}</PrivateKey>
    <CACertificate>{extracted_data['root_cert']}</CACertificate>
</WifiConfig>
""")
    print(f"[✓] Android Wi-Fi config written to {xml_path}")
    created_configs.append(f"{xml_path}")

def generate_netctl_config(created_configs, extracted_data, cert_path="/tmp/aqc/client.pem", key_path="/tmp/aqc/private_key.pem"):
    netctl_path = f"/tmp/aqc/netctl_{extracted_data['ssid']}"
    with open(netctl_path, "w") as f:
        f.write("""Description='{extracted_data['ssid']}'
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
        f.write("""[service_{extracted_data['ssid']}]
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
        f.write("""<network>
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

