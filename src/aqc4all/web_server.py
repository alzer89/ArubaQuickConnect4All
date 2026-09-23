# aqc4all/web_server.py

import http.server
import socket
import threading
import base64
import secrets
import string
import os
import urllib.parse
import segno
import functools
import uuid

class SecureAuthHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, server_auth_password="", wifi_username="", wifi_password="", wifi_ssid="", **kwargs):
        self.server_auth_password = server_auth_password
        self.wifi_username = wifi_username
        self.wifi_password = wifi_password
        self.wifi_ssid = wifi_ssid
        super().__init__(*args, **kwargs)

    server_auth_password = ""
    wifi_username = "N/A"
    wifi_password = "N/A"
    wifi_ssid = "Network with no wires"

    def address_string(self):
        return str(self.client_address[0])

    def do_HEAD(self):
        if self._authenticate():
            super().do_HEAD()

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_path.query)

        token = query_params.get("token", [None])[0]
        token_suffix = f"?token={token}" if token else ""

        if token and token == self.server_auth_password:
            # Bypass standard basic auth if valid token query param is present
            pass
        elif not self._authenticate():
            return

        forced_os = query_params.get("os", [None])[0]

        clean_path = parsed_path.path

        # Drop favicon requests instantly to prevent
        # remote browser hanging shenanigans
        if clean_path == '/favicon.ico':
            self.send_response(204) # No Content
            self.end_headers()
            return

        if clean_path == '/' or clean_path == '':
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()

            try:
                files = os.listdir(self.directory)
            except Exception:
                files = []

            # "Hi, I'm a Mac..." "...and I'm a PC"
            ua = self.headers.get("User-Agent", "")

            # Nice little OS detection
            platform_signatures = [
                # No idea what to do about game consoles...
                ("game_console", lambda u: any(k in u for k in ["PlayStation", "Nintendo", "Xbox"])),
                ("apple", lambda u: any(k in u for k in ["iPhone", "iPad", "iPod", "watchOS", "AppleTV", "Macintosh", "Mac OS X"])),
                # Windows has to come BEFORE Android, because the Nokia Lumia is technically 
                # a WINDOWS phone, and has both "Windows" and "Android" in the User_Agent
                ("windows", lambda u: any(k in u for k in ["Windows", "Win64"])),
                # Android has to come BEFORE Linux, because a lot of 
                # phones have "Linux; Android" in their User-Agent
                ("android", lambda u: "Android" in u),
                ("chromeos", lambda u: "CrOS" in u),
                # Anything that doesn't ALSO call itself something
                # else must be a Linux distro or a Linux phone...
                ("linux", lambda u: any(k in u for k in ["Linux", "Tizen", "OpenWRT"])),
                # BSD is always last, because they never
                # EVER pretend to be anything else ;-)
                ("bsd", lambda u: "bsd" in u.lower()),

            ]

            detected_platform = forced_os.lower() if forced_os else None

            if not detected_platform:
                # If the user is a moron, default back to Linux
                detected_platform = "linux"
                for plat_name, matcher in platform_signatures:
                    if matcher(ua):
                        detected_platform = plat_name
                        break

            # Build query helper links for the override switcher header
            base_url_params = f"/?token={token}" if token else "/"
            os_switcher_html = f"""
            <div style="text-align: center; margin-top: 15px; font-size: 12px; color: #666;">
                Wrong OS detected?
                <a href="{base_url_params}&os=linux">Linux</a> |
                <a href="{base_url_params}&os=bsd">BSD</a> |
                <a href="{base_url_params}&os=apple">Apple (iOS / iPadOS / WatchOS / tvOS / macOS)</a> |
                <a href="{base_url_params}&os=windows">Windows</a> |
                <a href="{base_url_params}&os=android">Android</a> |
                <a href="{base_url_params}&os=chromeos">ChromeOS</a> |
                <a href="{base_url_params}&os=game_console">Game Console</a> |
                <a href="{base_url_params}&os=tizen">TizenOS (Smart TVs)</a> |
                <a href="{base_url_params}&os=openwrt">OpenWRT</a> |
            </div>
            """

            win_xml = next((f for f in files if f.endswith("_windows.xml")), None)
            win_bat = next((f for f in files if f.startswith("install_") and f.endswith(".bat")), None)

            onc_file = next((f for f in files if f.endswith(".onc")), None)

            mobileconfig_file = next((f for f in files if f.endswith('.mobileconfig')), None)
            nmconnection_file = next((f for f in files if f.endswith('.nmconnection')), None)

            secure_p12_file = next((f for f in files if f.endswith('_client.p12')), None)
            ios_p12_file = next((f for f in files if f.endswith('_ios_client.p12')), None)

            ca_cert_file = next((f for f in files if 'ca_root.pem' in f), None)
            client_cert_file = next((f for f in files if 'client.pem' in f), None)
            client_key_file = next((f for f in files if 'private_key.pem' in f or 'private' in f), None)
            
            token_suffix = f"?token={self.server_auth_password}"

            primary_action_html = ""

            # Apple devices
            if detected_platform == "apple" and mobileconfig_file:
                primary_action_html = f"""
                <div class="highlight-box">
                    <span class="badge" style="background: #000000;">Apple Device</span>
                    <h3><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 170 170" style="vertical-align: middle; margin-right: 6px; fill: currentColor;"><path d="M150.37 130.25c-2.45 5.66-5.35 10.87-8.71 15.66-4.58 6.53-8.33 11.05-11.22 13.56-4.48 4.12-9.28 6.23-14.42 6.35-3.69 0-8.14-1.05-13.32-3.18-5.19-2.12-9.97-3.17-14.34-3.17-4.58 0-9.49 1.05-14.75 3.17-5.26 2.13-9.5 3.24-12.74 3.35-4.35.13-9.16-1.9-14.42-6.08-3.7-3.05-7.6-7.8-11.7-14.25-6.35-10.15-11.45-21.46-15.3-33.92-3.85-12.46-5.78-24.34-5.78-35.63 0-14.16 3.65-25.68 10.95-34.56 7.3-8.88 16.54-13.38 27.72-13.51 5.43 0 11.04 1.41 16.83 4.23 5.79 2.82 9.68 4.23 11.67 4.23 1.74 0 5.79-1.52 12.15-4.56 6.36-3.04 12.35-4.4 17.98-4.08 15.7 1.14 27.8 7.38 36.31 18.72-13.2 8.04-19.68 19.32-19.44 33.84.22 11.68 4.67 21.2 13.35 28.56 6.45 5.54 14.18 8.94 23.19 10.2-2.93 8.78-6.52 17.07-10.77 24.87zM119.22 31.81c0-7.84 2.79-15.24 8.37-22.2 5.58-6.96 12.63-10.95 21.15-11.97.11 1.09.17 2.07.17 2.94 0 7.84-2.82 15.35-8.46 22.53-5.64 7.18-12.72 11.23-21.24 12.15-.05-.87-.09-1.9-.09-3.09z"/></svg> 1-Tap Auto-Configuration</h3>
                    <p>Tap below to install your <code>{self.wifi_ssid}</code> profile:</p>
                    <a href="/{mobileconfig_file}{token_suffix}" class="btn">Install Profile ({mobileconfig_file})</a>
                </div>"""

            # POSIX devices
            elif (detected_platform == "tizen" or \
                    detected_platform == "openwrt" or \
                    detected_platform == "linux" or \
                    detected_platform == "bsd") \
                    and nmconnection_file:
                primary_action_html = f"""
                <div class="highlight-box" style="background: #f0f4f8; border: 1px solid #d0e1fd;">
                    <span class="badge" style="background: #731205;">BSD / Linux / Other POSIX</span>
                    <h3><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" style="vertical-align: middle; margin-right: 6px; fill: currentColor;"><path d="M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm-5 14H4v-2h11v2zm3-4H4v-2h14v2zm0-4H4V8h14v2z"/></svg> Here's the terminal commands you guys seem to love so much...</h3>
                    <p style="font-size: 13px; color: #555;">Step 1: Download your certs/keys.</p>

                    <!-- Certificate Downloads -->
                    <div style="margin: 15px 0;">
                        <a href="/{ca_cert_file}{token_suffix}" class="btn" style="background: #0055a5; margin-bottom: 8px;" download>Download CA Cert</a>
                        <a href="/{client_cert_file}{token_suffix}" class="btn" style="background: #0055a5; margin-bottom: 8px;" download>Download Client Cert</a>
                        <a href="/{client_key_file}{token_suffix}" class="btn" style="background: #28a745;" id="download-nm-btn" download>Download Client Key</a>
                    </div>

                    <!-- NIC Specification Form -->
                    <p style="font-size: 13px; color: #555;">Step 2: What's your NIC called?</p>
                    <div style="background: #fff; padding: 12px; border-radius: 6px; border: 1px solid #ccc; margin-top: 15px;">
                        <div style="margin-top: 8px;">
                            <label style="font-size: 12px; color: #555; display: block;">NIC Name:</label>
                            <input type="text" id="nic" value="wlan0" oninput="updatePosixConfigs()" style="width: 100%; padding: 6px; font-size: 13px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;" />
                        </div>
                    </div>


                    <!-- Path Configuration Form -->
                    <p style="font-size: 13px; color: #555;">Step 2: Specify where you put your certs/keys on your machine.</p>
                    <div style="background: #fff; padding: 12px; border-radius: 6px; border: 1px solid #ccc; margin-top: 15px;">
                        <strong style="font-size: 13px;">Filepaths on your machine:</strong>

                        <div style="margin-top: 8px;">
                            <label style="font-size: 12px; color: #555; display: block;">CA Certificate:</label>
                            <input type="text" id="path-ca" value="/etc/ssl/certs/ca_root.pem" oninput="updatePosixConfigs()" style="width: 100%; padding: 6px; font-size: 13px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;" />
                        </div>

                        <div style="margin-top: 8px;">
                            <label style="font-size: 12px; color: #555; display: block;">Client Certificate:</label>
                            <input type="text" id="path-cert" value="/etc/ssl/certs/client.pem" oninput="updatePosixConfigs()" style="width: 100%; padding: 6px; font-size: 13px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;" />
                        </div>

                        <div style="margin-top: 8px;">
                            <label style="font-size: 12px; color: #555; display: block;">Private Key:</label>
                            <input type="text" id="path-key" value="/etc/ssl/private/private_key.pem" oninput="updatePosixConfigs()" style="width: 100%; padding: 6px; font-size: 13px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;" />
                        </div>
                    </div>

                    <!-- Collapsible Setup Sections -->
                    <div style="margin-top: 15px;">
                        <!-- NetworkManager -->
                        <details open style="background: #fff; padding: 10px; border-radius: 6px; border: 1px solid #d0e1fd; margin-bottom: 8px;">
                            <summary>NetworkManager</summary>
                            <div class="code-block" id="conf-nm" style="white-space: pre-wrap;">
[connection]
id={self.wifi_ssid}
uuid={uuid.uuid4()}
type=wifi

[wifi]
mode=infrastructure
ssid={self.wifi_ssid}

[wifi-security]
key-mgmt=wpa-eap

[802-1x]
eap=tls
identity={self.wifi_username}
ca-cert=<span class="val-ca">/etc/ssl/certs/{ca_cert_file}</span>
client_cert=<span class="val-cert">/etc/ssl/certs/{client_cert_file}</span>
private_key=<span class="val-key">/etc/ssl/certs/{client_key_file}</span>
private-key-password-flags=0
private-key-password={self.wifi_password}
phase2-auth=mschapv2

[ipv4]
method=auto

[ipv6]
method=auto</div>
                            <br>
                            <p style="font-size: 12px; color: #666; margin: 8px 0;">Run these commands in your terminal to install:</p>
                            <div class="code-block" id="cmd-nm">
                                sudo cp {{nmconnection_file}} /etc/NetworkManager/system-connections/<br>
                                sudo chmod 600 /etc/NetworkManager/system-connections/{{nmconnection_file}}<br>
                                sudo systemctl restart NetworkManager<br>
                                # If you don't use systemd, then you already<br>
                                # KNOW what to type instead of these...<br>
                                # In fact, why don't you just stop being<br>
                                # lazy and RUN THIS ON YOUR OWN MACHINE...?<br>
                            </div>
                        </details>

                        <!-- wpa_supplicant -->
                        <details style="background: #fff; padding: 10px; border-radius: 6px; border: 1px solid #d0e1fd; margin-bottom: 8px;">
                            <summary>wpa_supplicant</summary>
                            <p style="font-size: 12px; color: #666; margin: 8px 0;">Add this block to your <code>/etc/wpa_supplicant/wpa_supplicant.conf</code>:</p>
                            <div class="code-block" id="cmd-wpa" style="white-space: pre-wrap;">
network={{
    ssid="{self.wifi_ssid}"
    key_mgmt=WPA-EAP
    eap=TLS
    identity="{self.wifi_username}"
    ca_cert="<span class="val-ca">/etc/ssl/certs/{ca_cert_file}</span>"
    client_cert="<span class="val-cert">/etc/ssl/certs/{client_cert_file}</span>"
    private_key="<span class="val-key">/etc/ssl/private/{client_key_file}</span>"
    private_key_passwd="{self.wifi_password}"
}}</div>
                        </details>

                        <!-- iwd -->
                        <details style="background: #fff; padding: 10px; border-radius: 6px; border: 1px solid #d0e1fd; margin-bottom: 8px;">
                            <summary>iwd (Intel Wireless Daemon)</summary>
                            <p style="font-size: 12px; color: #666; margin: 8px 0;">Create configuration file under <code>/var/lib/iwd/{self.wifi_ssid}.conf</code>:</p>
                            <div class="code-block" id="cmd-iwd" style="white-space: pre-wrap;">
[Security]
EAP-Method=TLS
EAP-Identity={self.wifi_username}
EAP-TLS-ClientCertificate=<span class="val-cert">/etc/ssl/certs/{client_cert_file}</span>
EAP-TLS-ClientKey=<span class="val-key">/etc/ssl/private/{client_key_file}</span>
EAP-TLS-RootCACertificate=<span class="val-ca">/etc/ssl/certs/{ca_cert_file}</span></div>
                        </details>

                       <!-- systemd-networkd / iNet wireless -->
                       <details style="background: #fff; padding: 10px; border-radius: 6px; border: 1px solid #d0e1fd; margin-bottom: 8px;">
                           <summary>systemd-networkd (+ wpa_supplicant backend)</summary>
                           <p style="font-size: 12px; color: #666; margin: 8px 0;">systemd-networkd relies on wpa_supplicant for enterprise Wi-Fi. Ensure your `.network` file matches your interface, and use the wpa_supplicant block above.</p>
                           <div class="code-block" id="cmd-networkd" style="white-space: pre-wrap;">
[Match]
Name=wlan*

[Network]
DHCP=yes</div>
                       </details>

                       <!-- wicked -->
                       <details style="background: #fff; padding: 10px; border-radius: 6px; border: 1px solid #d0e1fd; margin-bottom: 8px;">
                           <summary>wicked (openSUSE)</summary>
                           <p style="font-size: 12px; color: #666; margin: 8px 0;">Configure your network interface profile under <code>/etc/wicked/ifcfg-{self.wifi_ssid}</code>:</p>
                           <div class="code-block" id="cmd-wicked" style="white-space: pre-wrap;">
NAME="{self.wifi_ssid}"
STARTMODE="auto"
WIRELESS="yes"
WIRELESS_ESSID="{self.wifi_ssid}"
WIRELESS_SECURITY_MODE="wpa2"
WIRELESS_EAP_METHOD="TLS"
WIRELESS_EAP_IDENTITY="{self.wifi_username}"
WIRELESS_CA_CERT="<span class="val-ca">/etc/ssl/certs/{ca_cert_file}</span>"
WIRELESS_CLIENT_CERT="<span class="val-cert">/etc/ssl/certs/{client_cert_file}</span>"
WIRELESS_CLIENT_KEY="<span class="val-key">/etc/ssl/private/{client_key_file}</span>"
WIRELESS_CLIENT_KEY_PASSWORD="{self.wifi_password}"</div>
                       </details>

                       <!-- connman -->
                       <details style="background: #fff; padding: 10px; border-radius: 6px; border: 1px solid #d0e1fd; margin-bottom: 8px;">
                           <summary>connman</summary>
                           <p style="font-size: 12px; color: #666; margin: 8px 0;">Create a provisioning file under <code>/var/lib/connman/{self.wifi_ssid}.config</code>:</p>
                           <div class="code-block" id="cmd-connman" style="white-space: pre-wrap;">
[global]
Name = {self.wifi_ssid}
Description = EAP-TLS Wi-Fi on MY terms

[service_{self.wifi_ssid}]
Type = wifi
Name = {self.wifi_ssid}
EAP = tls
Identity = {self.wifi_username}
CACertFile = <span class="val-ca">/etc/ssl/certs/{ca_cert_file}</span>
ClientCertFile = <span class="val-cert">/etc/ssl/certs/{client_cert_file}</span>
PrivateKeyFile = <span class="val-key">/etc/ssl/private/{client_key_file}</span>
PrivateKeyPassphrase = {self.wifi_password}</div>
                       </details>

                       <!-- netctl -->
                       <details style="background: #fff; padding: 10px; border-radius: 6px; border: 1px solid #d0e1fd;">
                           <summary>netctl (Arch Linux)</summary>
                           <p style="font-size: 12px; color: #666; margin: 8px 0;">Create a profile under <code>/etc/netctl/{self.wifi_ssid}</code>:</p>
                           <div class="code-block" id="cmd-netctl" style="white-space: pre-wrap;">
Description="{self.wifi_ssid} EAP-TLS connection"
Interface="<span class="nic">wlan0</span>"
Connection="wireless"
Security="wpa-configsection"
IP="dhcp"
WPAConfigSection=(
    'ssid="{self.wifi_ssid}"'
    'key_mgmt=WPA-EAP'
    'eap=TLS'
    'identity="{self.wifi_username}"'
    'ca_cert="<span class="val-ca">/etc/ssl/certs/{ca_cert_file}</span>"'
    'client_cert="<span class="val-cert">/etc/ssl/certs/{client_cert_file}</span>"'
    'private_key="<span class="val-key">/etc/ssl/private/{client_key_file}</span>"'
    'private_key_passwd="{self.wifi_password}"'
)</div>
                       </details>

                       <!-- OpenWRT -->
                       <details style="background: #fff; padding: 10px; border-radius: 6px; border: 1px solid #d0e1fd;">
                           <summary>OpenWRT</summary>
                           <p style="font-size: 12px; color: #666; margin: 8px 0;">Append this to <code>/etc/config/network</code>:</p>
                           <div class="code-block" id="cmd-openwrt" style="white-space: pre-wrap;">
config wifi-iface 'eap_tls_client'
    option device '<span class="nic">radio0</span>'
    option mode 'sta'
    option ssid '{self.wifi_ssid}'
    option network 'wwan'
    option encryption 'wpa2-eap'
    option eap_type 'tls'
    option identity '{self.wifi_username}'
    option ca_cert '<span class="val-ca">/etc/ssl/certs/{ca_cert_file}</span>'
    option client_cert '<span class="val-cert">/etc/ssl/certs/{client_cert_file}</span>'
    option private_key '<span class="val-key">/etc/ssl/private/{client_key_file}</span>'
    option private_key_passwd '{self.wifi_password}'

                       </details>
                    </div>
                </div>"""
                           
            # Android devices
            elif detected_platform == "android":
                primary_action_html = f"""
                <div class="highlight-box" style="background: #f0f4f8; border: 1px solid #d0e1fd;">
                    <span class="badge" style="background: #3ddc84;">Android</span>
                    <h3 style="margin-top: 8px;"><svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" style="vertical-align: middle; margin-right: 6px; fill: currentColor;"><path d="M17.523 15.341c.455 0 .825-.37.825-.825v-4.125a.825.825 0 0 0-.825-.825.825.825 0 0 0-.825.825v4.125c0 .455.37.825.825.825zm-11.046 0c.455 0 .825-.37.825-.825v-4.125a.825.825 0 0 0-.825-.825.825.825 0 0 0-.825.825v4.125c0 .455.37.825.825.825zm11.282-9.431l1.554-2.693a.412.412 0 0 0-.151-.563.413.413 0 0 0-.563.151l-1.579 2.735a11.243 11.243 0 0 0-4.084-.799c-1.465 0-2.868.286-4.084.799L6.378 2.495a.413.413 0 0 0-.563-.151.412.412 0 0 0-.151.563l1.554 2.693C4.945 7.176 3.75 9.17 3.375 11.454h17.25c-.375-2.284-1.57-4.278-3.076-5.544zM8.25 8.25a.75.75 0 1 1 0-1.5.75.75 0 0 1 0 1.5zm7.5 0a.75.75 0 1 1 0-1.5.75.75 0 0 1 0 1.5zM3.375 12.375h17.25V18c0 1.243-1.007 2.25-2.25 2.25h-1.125v1.875a.75.75 0 1 1-1.5 0V20.25H9.75v1.875a.75.75 0 1 1-1.5 0V20.25H7.125c-1.243 0-2.25-1.007-2.25-2.25v-5.625z"/></svg> Android Setup Instructions</h3>
                    <p style="font-size: 13px; color: #555;">Because Android only lets you install 1-tap configs via Mobile Device Management, you will have to do the steps yourself. But don't worry, we have made it as easy as possible.</p>

                    <!-- Download Certs Box -->
                    <div style="margin: 15px 0;">
                        <a href="/{ca_cert_file}{token_suffix}" class="btn" style="background: #0055a5; margin-bottom: 8px;" download>Step 1: Download Root CA Certificate</a>
                        <a href="/{secure_p12_file}{token_suffix}" class="btn" style="background: #0055a5;" download>Step 2: Download Client Bundle (.p12)</a>
                    </div>

                    <!-- Step-by-step checklist instructions -->
                    <div style="background: #fff; padding: 12px; border-radius: 6px; font-size: 13px; border: 1px solid #d0e1fd; margin-top: 15px; line-height: 1.5;">
                        <strong>Step 3: Install Certificates:</strong><br>
                        1. Go to <em>Settings &gt; Security &amp; privacy &gt; More security and privacy &gt; Encryption &amp; credentials &gt; Install a certificate</em>.<br>
                        2. Tap <strong>Wi-Fi certificate</strong></em>.<br>
                        3. Select your <code>.p12</code> file.<br>
                        4. Enter the unlocking passphrase when requested:<br>
                        <input type="text" readonly value="{self.wifi_password}" onclick="this.select();" style="width: 100%; padding: 6px; font-size: 13px; border: 1px solid #ccc; border-radius: 4px; background: #fff; box-sizing: border-box;" />
                        <button onclick="copyTextToClipboard('{self.wifi_password}', this)" style="...">Copy</button><br>
                        <strong>OPTIONAL:</strong><br>
                        5. Go back and tap <strong>CA certificate</strong>.<br>
                        6. <strong>READ CAREFULLY, AND ONLY IF YOU ARE OK WITH IT</strong>, click <strong>Accept/Install</strong>.<br>
                        7. Select your CA file.<br>
                        <br>
                    </div>

                    <!-- Copy Configs Box -->
                    <strong>Step 4: Connect to {self.wifi_ssid}:</strong><br>
                    <div style="background: #fff; padding: 12px; border-radius: 6px; border: 1px solid #ccc; margin-top: 15px;">
                        <br>Go to Settings &gt; Wi-Fi &gt; {self.wifi_ssid}<br>

                        <div style="margin-top: 8px; background: #f8f9fa; padding: 8px; border-radius: 4px;">
                            <label style="font-size: 12px; color: #555; display: block; margin-bottom: 2px;">EAP method:</label>
                            <input type="text" readonly value="TLS" onclick="this.select();" style="width: 100%; padding: 6px; font-size: 13px; border: 1px solid #ccc; border-radius: 4px; background: #fff; box-sizing: border-box;" />
                        </div>

                        <div style="margin-top: 8px; background: #f8f9fa; padding: 8px; border-radius: 4px;">
                            <label style="font-size: 12px; color: #555; display: block; margin-bottom: 2px;">CA certificate:</label>
                            <input type="text" readonly value="Trust on first use (or Install certificates if you prefer)" onclick="this.select();" style="width: 100%; padding: 6px; font-size: 13px; border: 1px solid #ccc; border-radius: 4px; background: #fff; box-sizing: border-box;" />
                        </div>

                        <div style="margin-top: 8px; background: #f8f9fa; padding: 8px; border-radius: 4px;">
                            <label style="font-size: 12px; color: #555; display: block; margin-bottom: 2px;">Minimum TLS version:</label>
                            <input type="text" readonly value="(The highest the remote server will take)" onclick="this.select();" style="width: 100%; padding: 6px; font-size: 13px; border: 1px solid #ccc; border-radius: 4px; background: #fff; box-sizing: border-box;" />
                        </div>

                        <div style="margin-top: 8px; background: #f8f9fa; padding: 8px; border-radius: 4px;">
                            <label style="font-size: 12px; color: #555; display: block; margin-bottom: 2px;">Domain (if required):</label>
                            <input type="text" readonly value="(Usually what's at the end of your username)" onclick="this.select();" style="width: 100%; padding: 6px; font-size: 13px; border: 1px solid #ccc; border-radius: 4px; background: #fff; box-sizing: border-box;" />
                        </div>

                        <div style="margin-top: 8px; background: #f8f9fa; padding: 8px; border-radius: 4px;">
                            <label style="font-size: 12px; color: #555; display: block; margin-bottom: 2px;">User certificate:</label>
                            <input type="text" readonly value="(Your .p12 file)" onclick="this.select();" style="width: 100%; padding: 6px; font-size: 13px; border: 1px solid #ccc; border-radius: 4px; background: #fff; box-sizing: border-box;" />
                        </div>

                        <div style="margin-top: 8px; background: #f8f9fa; padding: 8px; border-radius: 4px;">
                            <label style="font-size: 12px; color: #555; display: block; margin-bottom: 2px;">Identity:</label>
                            <input type="text" readonly value="{self.wifi_username}" onclick="this.select();" style="width: 100%; padding: 6px; font-size: 13px; border: 1px solid #ccc; border-radius: 4px; background: #fff; box-sizing: border-box;" />
                            <button onclick="copyTextToClipboard('{self.wifi_username}', this)" style="...">Copy</button>
                        </div>

                        <div style="margin-top: 8px; background: #f8f9fa; padding: 8px; border-radius: 4px;">
                            <label style="font-size: 12px; color: #555; display: block; margin-bottom: 2px;">P12 Bundle Passphrase:</label>
                            <input type="text" readonly value="{self.wifi_password}" onclick="this.select();" style="width: 100%; padding: 6px; font-size: 13px; border: 1px solid #ccc; border-radius: 4px; background: #fff; box-sizing: border-box;" />
                            <button onclick="copyTextToClipboard('{self.wifi_password}', this)" style="...">Copy</button>
                        </div>
                    </div>
               </div>"""

            # Windows devices
            elif detected_platform == 'windows':
                primary_action_html = f"""
                    <div class="highlight-box">
                        <span class="badge" style="background:#f4b400; color:#357ec7;">Windows</span>
                        <h3>1-Click Windows Profile Setup</h3>
                        <p style="font-size: 13px; margin-bottom: 10px;">
                            We detected you are running Windows. Download and run the automated installer batch script to configure your network instantly.
                        </p>
                        <a class="btn" href="/{win_xml}{token_suffix}">Download WWAN XML (.xml)</a>
                        <a class="btn" href="/{win_bat}{token_suffix}">Download & Run Installer (.bat)</a>
                        <details style="margin-top: 12px;">
                            <summary>Advanced / Manual Setup Files</summary>
                            <p style="font-size: 12px; color: #666; margin-top: 5px;">
                                You can also manually import the WLAN XML profile (<code style="background:#f1f3f4; padding:2px 4px; border-radius:3px;">{win_xml}</code>) via command prompt using <code style="background:#f1f3f4; padding:2px 4px; border-radius:3px;">netsh wlan add profile</code>.
                            </p>
                        </details>
                    </div>
               </div>"""

            # Chromebooks
            elif detected_platform == "chromeos":
                primary_action_html = f"""
                    <div class="highlight-box">
                        <span class="badge" style="background:#f4b400; color:#ffa700;">ChromeOS</span>
                        <h3>Chromebook ONC Network Setup</h3>
                        <p style="font-size: 13px; margin-bottom: 10px;">
                            Download your Open Network Configuration (<code style="background:#f1f3f4; padding:2px 4px; border-radius:3px;">.onc</code>) file.<br>
                            Go to your Chromebook's internet settings or open a browser tab to <br><code style="background:#f1f3f4; padding:2px 4px; border-radius:3px;">chrome://network#general</code> to import it.<br>
                        </p>
                        <a class="btn" href="/{onc_file}{token_suffix}" download>Download ONC Profile</a>
                    </div>
               </div>"""

            # Game Consoles
            elif detected_platform == "game_console":
                primary_action_html = f"""
                    <div class="highlight-box">
                        <span class="badge" style="background:#f4b400; color:#ffa700;">Game Console</span>
                        <h3>Setup Instructions</h3>
                        <p style="font-size: 13px; margin-bottom: 10px;">
                            You want to connect a game console to enterprise Wi-Fi?<br>
                            You're either a corporate game developer, or your homelab is on steroids!<br>
                            Just get an ethernet cable, you maniac!<br>You'll get lower latency that way, too...<br>
                        </p>
                        <a class="btn" href="https://en.wikipedia.org/wiki/Loot_box">Lootbox</a>
                    </div>
               </div>"""

            # Catch-all
            else:
                primary_action_html = f"""
                    <div class="highlight-box">
                        <span class="badge" style="background:#f4b400; color:#000000;">Moron Detected</span>
                        <h1>💀</h1>
                        <p style="font-size: 13px; margin-bottom: 10px;">
                            Doesn't exist, you dopey blockhead!<br>
                            Try something else...<br>
                        </p>
                        <a class="btn" href="https://en.wikipedia.org/wiki/Grass">Touch Grass</a>
                    </div>
               </div>"""


            # The certs get placed first, 
            # followed by everything else
            def file_sort_key(filename):
                fn = filename.lower()
                if fn.endswith('.p12'):
                    return (0, fn)
                elif fn.endswith('.pem'):
                    return (1, fn)
                elif '.crt' in fn:
                    return (2, fn)
                else:
                    return (3, fn)

            download_links_html = ""
            for f in sorted(files, key=file_sort_key):
                if f.startswith('.'):
                    continue
                download_links_html += f'<li><a href="/{f}{token_suffix}" download> <code>{f}</code></a></li>\n'

            html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Aruba QuickConnect - {self.wifi_ssid}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f4f6f9; color: #333; margin: 0; padding: 15px; }}
        .card {{ background: #fff; border-radius: 12px; padding: 20px; max-width: 600px; margin: 0 auto; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }}
        h1 {{ font-size: 20px; color: #0055a5; margin-top: 0; }}
        h3 {{ font-size: 15px; color: #222; margin-bottom: 8px; }}
        .creds {{ background: #eef4fb; border-left: 4px solid #0055a5; padding: 12px; border-radius: 4px; margin: 15px 0; font-family: monospace; font-size: 14px; }}
        ul {{ padding-left: 20px; margin-top: 5px; }}
        li {{ margin-bottom: 6px; font-size: 14px; }}
        a {{ color: #0055a5; text-decoration: none; font-weight: bold; }}
        a:hover {{ text-decoration: underline; }}
        .highlight-box {{ background: #e6f4ea; border: 1px solid #ceead6; border-radius: 8px; padding: 15px; margin-bottom: 20px; }}
        .badge {{ background: #137333; color: white; font-size: 11px; padding: 3px 8px; border-radius: 10px; font-weight: bold; text-transform: uppercase; }}
        .btn {{ display: block; background: #0055a5; color: white; text-align: center; padding: 10px; border-radius: 6px; margin-top: 5px; font-size: 14px; }}
        .btn:hover {{ background: #003d7a; color: white; text-decoration: none; }}
        .code-block {{ background: #202124; color: #f8f9fa; padding: 10px; border-radius: 6px; font-family: monospace; font-size: 12px; overflow-x: auto; margin-top: 8px; line-height: 1.4; }}
        .section {{ margin-top: 20px; border-top: 1px solid #eee; padding-top: 15px; }}
        details {{ margin-top: 10px; font-size: 13px; color: #555; cursor: pointer; }}
        summary {{ font-weight: bold; font-size: 14px; color: #0055a5; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>ArubaQuickConnect4All - {self.wifi_ssid}</h1>
        <p style="font-size: 13px; color: #666;">Finally, I can connect to enterprise networks on MY terms.</p>
        {os_switcher_html}

        {primary_action_html}
        <div class="creds">
            <p style="font-size: 13px; color: #666;">Just in case you need any of the config info:</p>
            <strong>Target SSID:</strong> {self.wifi_ssid}<br>
            <strong>Network Identity:</strong> {self.wifi_username}<br>
            <strong>Certificate Decryption Password:</strong> {self.wifi_password}
        </div>

        <div class="section">
            <h3>All Generated Config Files (for tinkerers):</h3>
            <ul>
                {download_links_html}
            </ul>
        </div>
    </div>

    <script>
        function copyTextToClipboard(text, buttonEl) {{
            navigator.clipboard.writeText(text).then(() => {{
                const originalText = buttonEl.innerText;
                buttonEl.innerText = 'Copied!';
                setTimeout(() => buttonEl.innerText = originalText, 2000);
            }});
        }}

        function updatePosixConfigs() {{
            const caVal = document.getElementById('path-ca').value;
            const certVal = document.getElementById('path-cert').value;
            const keyVal = document.getElementById('path-key').value;
            const nicVal = document.getElementById('nic').value;

            // Update all text spans matching class selectors
            document.querySelectorAll('.val-ca').forEach(el => el.innerText = caVal);
            document.querySelectorAll('.val-cert').forEach(el => el.innerText = certVal);
            document.querySelectorAll('.val-key').forEach(el => el.innerText = keyVal);
            document.querySelectorAll('.nic').forEach(el => el.innerText = nicVal);

            // Dynamically update config block layout
            const nmCmdBlock = document.getElementById('cmd-nm');
            if (nmCmdBlock) {{
                nmCmdBlock.innerHTML =
                    `sudo cp {{nmconnection_file}} /etc/NetworkManager/system-connections/<br>` +
                    `# Ensure your client certs referenced inside are placed at: <br>` +
                    `# CA: ${{caVal}}<br>` +
                    `# Cert: ${{certVal}}<br>` +
                    `# Key: ${{keyVal}}<br>` +
                    `sudo systemctl restart NetworkManager`;
            }}
        }}
    </script>
</body>
</html>
"""
            try:
                self.wfile.write(html_content.encode('utf-8'))
            except (BrokenPipeError, ConnectionResetError):
                return
            return

        self.path = clean_path
        super().do_GET()

    def _authenticate(self):
        expected_auth = base64.b64encode(f"aruba:{self.server_auth_password}".encode()).decode()
        auth_header = self.headers.get("Authorization")

        if auth_header == f"Basic {expected_auth}":
            return True

        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="ArubaQuickConnect Secure Download"')
        self.send_header("Content-type", "text/html")
        self.end_headers()
        try:
            self.wfile.write(b"Unauthorized.")
        except (BrokenPipeError, ConnectionResetError):
            pass
        return False

    def log_message(self, format, *args):
        print(f"[web_server] {self.client_address[0]} - - {format%args}")

def launch_secure_qr_server(target_dir="/tmp/aqc", port=8080, extracted_data=None):
    os.makedirs(target_dir, exist_ok=True)
    if extracted_data is None:
        extracted_data = {}

    server_auth_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))

    wifi_user = extracted_data.get("username") or "Who am I?"
    wifi_pass = extracted_data.get("password") or "Open Sesame"
    wifi_ssid = extracted_data.get("ssid") or "Network on duh Airwavez"

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()

    handler_class = functools.partial(
        SecureAuthHandler, 
        directory=target_dir,
        server_auth_password=server_auth_password,
        wifi_username=wifi_user,
        wifi_password=wifi_pass,
        wifi_ssid=wifi_ssid
    )

    server = http.server.HTTPServer(('0.0.0.0', port), handler_class)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    url = f"http://{local_ip}:{port}/?token={server_auth_password}"

    print("\n" + "="*65)
    print("CONFIG DOWNLOAD SERVER ACTIVE")
    print("\n" + "="*65)
    print(f"URL (QR Auto-Login): {url}")
    print(f"Target SSID        : {wifi_ssid}")
    print(f"Network Identity   : {wifi_user}")
    print(f"Serving files from : {target_dir}")
    print("="*65)
    print("Scan the QR code below with your device:\n")

    try:
        qr = segno.make(url)
        qr.terminal(compact=True)
    except Exception as e:
        print(f"[!] Could not render terminal QR code: {e}")

    try:
        input("\nPress [Enter] to stop the server once files are downloaded...")
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        print("[*] Local sharing server shut down.")
