import os
import re
import tempfile
import zipfile
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.common.by import By
import time
import requests
import shutil
import pyotp

def get_browser_driver_path(browser_name):
    candidates = ["/usr/bin", "/usr/local/bin", shutil.which(browser_name)]
    for path in filter(None, candidates):
        if shutil.which(browser_name, path=path):
            return shutil.which(browser_name, path=path)
    return None

def launch_browser(args, USER_AGENT):
    browser_choice = args.browser.lower() if args.browser else "chromium"

    if browser_choice == "firefox":
        # Fix for Firefox Snap profile access issue
        os.environ["TMPDIR"] = os.path.expanduser("~/tmp")
        os.makedirs(os.environ["TMPDIR"], exist_ok=True)

        geckodriver_path = get_browser_driver_path("geckodriver")
        if not geckodriver_path:
            raise FileNotFoundError("geckodriver not found in PATH")

        print("[+] Running with Firefox browser (private mode)")

        # Set the path for a custom profile root (optional but recommended for sandboxed environments)
        profile_root = os.path.join(os.path.expanduser("~"), ".mozilla", "selenium_profiles")

        # Ensure the directory exists
        os.makedirs(profile_root, exist_ok=True)

        # Set User-Agent
        profile = FirefoxProfile()
        profile.set_preference("general.useragent.override", USER_AGENT)

        # Configure Firefox options
        options = FirefoxOptions()
        options.add_argument(f"--profile-root={profile_root}") # added profile-root

        service = FirefoxService(executable_path=geckodriver_path)
        return webdriver.Firefox(service=service, options=options)

    elif browser_choice == "chromium":
        chromedriver_path = get_browser_driver_path("chromedriver")
        if not chromedriver_path:
            raise FileNotFoundError("chromedriver not found in PATH")

        options = ChromeOptions()
        print("[+] Running with Chromium browser")
        options.add_argument("--disable-save-password-bubble")
        prefs = {"credentials_enable_service": False, "profile.password_manager_enabled": False}
        options.add_experimental_option("prefs", prefs)
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)
        options.add_argument(f"--user-agent={USER_AGENT}")
        service = ChromeService(executable_path=chromedriver_path)
        return webdriver.Chrome(service=service, options=options)

    else:
        raise ValueError("Unsupported browser: use 'chromium' or 'firefox'")

from playwright.sync_api import sync_playwright
import time

def login_and_get_token(args, USER_AGENT, BASE_URL, USERNAME, PASSWORD, TOTP_SECRET):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()
        page.goto(onboard_url)

        # Microsoft login page:
        page.fill('input[type="email"]', username)
        page.click('input[type="submit"]')
        page.wait_for_selector('input[type="password"]', timeout=60000)
        page.fill('input[type="password"]', password)
        page.click('input[type="submit"]')
        page.wait_for_selector('input[type="password"]', timeout=60000)
        page.fill('input[type="password"]', password)
        page.click('input[type="submit"]')

        # Wait for TOTP manually
        print("Please complete TOTP in browser, then press Enter...")
        input()

        # Wait until redirected back to onboarding path
        page.wait_for_url("**/onboard/**", timeout=120000)
        current_url = page.url
        print("Redirected to:", current_url)

        # At this point you can retrieve GSID or other query params
        browser.close()
        return current_url

def perform_login_and_extract_gsid(args, USER_AGENT, BASE_URL, USERNAME, PASSWORD, TOTP_SECRET):
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    print("[*] Launching browser...")
    driver = launch_browser(args, USER_AGENT)
    try:
        print(f"[*] Navigating browser to onboarding URL: {BASE_URL}")
        driver.get(BASE_URL)
        print("[*] Current URL after navigation:", driver.current_url)

        print("[>] Microsoft login page loaded")

        time.sleep(2)
        if USERNAME:
            username_input = driver.find_element(By.NAME, "loginfmt")
            username_input.send_keys(USERNAME)
            print("[>] Entered username")
            driver.find_element(By.ID, "idSIButton9").click()
        else:
            print("[*] Please enter username manually in the browser window.")

        time.sleep(3)
        if PASSWORD:
            password_input = driver.find_element(By.NAME, "passwd")
            password_input.send_keys(PASSWORD)
            print("[>] Entered password")
            driver.find_element(By.ID, "idSIButton9").click()
        else:
            print("[*] Please enter password manually in the browser window.")

        time.sleep(5)
        if TOTP_SECRET:
            if "Enter code" in driver.page_source or "Verify your identity" in driver.page_source:
                totp = pyotp.TOTP(TOTP_SECRET)
                code = totp.now()
                code_input = driver.find_element(By.NAME, "otc")
                code_input.send_keys(code)
                print(f"[>] Entered TOTP code: {code}")
                driver.find_element(By.ID, "idSubmit_SAOTCC_Continue").click()
        else:
            print("[*] Waiting for user to manually enter TOTP and continue login...")
            start_time = time.time()
            max_wait = 120  # seconds
            while time.time() - start_time < max_wait:
                if "mdps_qc_profile.php?GSID=" in driver.page_source:
                    print("[✓] TOTP accepted, continuing...")
                    break
                time.sleep(2)
            else:
                print("[!] Timed out waiting for TOTP submission.")

        time.sleep(2)
        if driver.find_elements(By.ID, "idSIButton9"):
            driver.find_element(By.ID, "idSIButton9").click()
            print("[>] Clicked 'Stay signed in'")

        time.sleep(3)
        print("[*] Waiting for portal return URL with onboard path...")
        start_time = time.time()
        gsid = None
        max_wait = 60

        while time.time() - start_time < max_wait:
            page = driver.page_source
            match = re.search(r'mdps_qc_profile\.php\?GSID=([a-z0-9]+)', page)
            if match:
                gsid = match.group(1)
                print("[✓] Found GSID:", gsid)
                download_url = f"{BASE_URL}/onboard/mdps_qc_profile.php?GSID={gsid}"
                print("[✓] Direct download URL:", download_url)
                break
            time.sleep(2)
        if not gsid:
            print("[!] GSID not found within timeout.")
            download_url = None
    except Exception as e:
        print(f"[!] Exception encountered during login process: {e}")
        download_url = None

    cookies = driver.get_cookies()
    driver.quit()
    return download_url, cookies


def download_script(download_url, cookies, USER_AGENT, output_path="/tmp/ArubaQuickConnect.sh"):
    import requests
    if not download_url:
        print("[!] No download URL provided, skipping download.")
        return

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    for cookie in cookies:
        session.cookies.set(cookie['name'], cookie['value'])

    print(f"[*] Downloading script from: {download_url}")
    response = session.get(download_url, allow_redirects=True)
    if response.status_code == 200:
        with open(output_path, "wb") as f:
            f.write(response.content)
        print(f"[✓] Script downloaded: {output_path}")
    else:
        print(f"[!] Failed to download. Status code: {response.status_code}")

def extract_embedded_tar(output_path="/tmp/ArubaQuickConnect.sh"):
    print("[*] Extracting embedded tar.bz2...")

    with open(output_path, "rb") as f:
        content = f.read()

    # Find the start of the binary archive by counting lines
    split_index = 0
    line_count = 0
    for i, byte in enumerate(content):
        if byte == ord('\n'):
            line_count += 1
            if line_count == 504:
                split_index = i + 1
                break

    archive_data = content[split_index:]

    temp_tar_path = "/tmp/aqc/ArubaQuickConnect.tar.bz2"
    os.makedirs("/tmp/aqc", exist_ok=True)
    with open(temp_tar_path, "wb") as f:
        f.write(archive_data)

    shutil.unpack_archive(temp_tar_path, "/tmp/aqc")
    print("[✓] Extracted to /tmp/aqc")

