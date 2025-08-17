import requests
import hashlib
import base64
from urllib.parse import urlparse
import re
import json
import time

ROUTER_URL = "http://192.168.100.108"
LOGIN_PATH = "/userRpm/LoginRpm.htm"
USERNAME = "admin"  # Replace with your username
PASSWORD = "admin"  # Replace with your password

def md5_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def get_auth_cookie(username, password, use_md5=True):
    if use_md5:
        password = md5_hash(password)
    auth_str = f"{username}:{password}"
    b64_auth = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
    return f"Basic {b64_auth}"

def login():
    session = requests.Session()
    auth_cookie = get_auth_cookie(USERNAME, PASSWORD, use_md5=True)
    session.cookies.set("Authorization", auth_cookie, path="/")
    login_url = ROUTER_URL + LOGIN_PATH
    params = {"Save": "Save"}
    resp = session.get(login_url, params=params, allow_redirects=True)
    if resp.status_code == 200:
        print("Login successful.")
        return session, resp.url, resp.text
    else:
        print("Login failed.")
        return None, None, None

def extract_token_from_response(resp_text):
    match = re.search(r'/([A-Z]{14})/userRpm/Index\.htm', resp_text)
    if match:
        return match.group(1)
    return None

def extract_token_from_url(url):
    match = re.search(r'/([A-Z]{14})/userRpm/Index\.htm', url)
    if match:
        return match.group(1)
    return None

def parse_response(resp_text):
    match = re.search(r'href\s*=\s*"([^"]+)"', resp_text)
    if match:
        url = match.group(1)
    else:
        print("No URL found")
        return None
    path_parts = urlparse(url).path.strip("/").split("/")
    if len(path_parts) >= 2:
        return path_parts[0]
    else:
        print("URL does not have a second path segment")
        return None

def retrieve_wireless_devices(session, token):
    # Add 500ms delay before scraping
    time.sleep(0.5)
    # Original JSON fetch for reference; retain if your model supports it.
    status_url = f"{ROUTER_URL}/{token}/data/map_access_wireless_client_grid.json"
    headers = {
        "Referer": f"{ROUTER_URL}/{token}/userRpm/BasicNetworkMapRpm.htm",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Origin": ROUTER_URL,
        "X-Requested-With": "XMLHttpRequest"
    }
    response = session.get(status_url, headers=headers)
    print("\n--- RAW RESPONSE FROM ROUTER (JSON) ---")
    print(response.text)
    print("--- END RAW RESPONSE ---\n")
    return response.text

def retrieve_wireless_clients_html(session, token):
    
    time.sleep(0.5)
    # Fetch the standard HTML endpoint for wireless stations.
    status_url = f"{ROUTER_URL}/{token}/userRpm/WlanStationRpm.htm"
    headers = {
        "Referer": f"{ROUTER_URL}/{token}/userRpm/Index.htm",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    }
    response = session.get(status_url, headers=headers)
    print("\n--- RAW RESPONSE FROM ROUTER (HTML) ---")
    print(response.text)
    print("--- END RAW RESPONSE ---\n")
    return response.text

def print_connected_devices(session, token):
    # First, try the original JSON approach.
    json_text = retrieve_wireless_devices(session, token)
    if json_text:
        try:
            data = json.loads(json_text)
            devices = []
            if 'data' in data and isinstance(data['data'], list):
                devices = data['data']
            elif 'grid' in data and isinstance(data['grid'], list):
                devices = data['grid']
            if devices:
                print(f"Total connected devices (from JSON): {len(devices)}")
                for idx, device in enumerate(devices, 1):
                    mac = device.get('mac', device.get('MAC', 'N/A'))
                    hostname = device.get('hostname', device.get('hostName', 'N/A'))
                    print(f"{idx}. MAC: {mac} | Host Name: {hostname}")
                return  # Exit if JSON succeeds.
            else:
                print("No device list found in JSON response.")
        except Exception as e:
            print("Error parsing JSON:", e)

    # Fallback to HTML scraping if JSON fails.
    html_text = retrieve_wireless_clients_html(session, token)
    if not html_text:
        print("No data received from HTML endpoint.")
        return

    try:
        # Extract the embedded stationList array from the HTML.
        match = re.search(r'var stationList = new Array\(\s*(.*?)\s*\);', html_text, re.DOTALL)
        if not match:
            print("Could not find stationList in HTML response.")
            return

        array_str = match.group(1).strip()
        # Split the array elements; each device is a set of values like "MAC", "Associated", "Authorized", etc.
        elements = re.findall(r'"([^"]*)"|(\d+)', array_str)
        elements = [e[0] if e[0] else e[1] for e in elements]

        # Devices are grouped in fixed-length tuples (typically 10-12 fields per device, depending on model).
        # Common fields: MAC, Associated, Authorized, Encrypted, Cipher, RSSI, Band Width, Mode, Rx Pkt, Tx Pkt, etc.
        field_count = 10  # Example; verify from raw response.
        devices = [elements[i:i+field_count] for i in range(0, len(elements), field_count) if len(elements[i:i+field_count]) == field_count]

        print(f"Total connected wireless devices (from HTML): {len(devices)}")
        for idx, device in enumerate(devices, 1):
            print(f"{idx}. Details:")
            print(f"   MAC: {device[0]}")
            print(f"   Associated: {device[1]}")
            print(f"   Authorized: {device[2]}")
            print(f"   Encrypted: {device[3]}")
            print(f"   Cipher: {device[4]}")
            print(f"   RSSI (Signal): {device[5]}")
            print(f"   Band Width: {device[6]}")
            print(f"   Mode: {device[7]}")
            print(f"   Rx Packets: {device[8]}")
            print(f"   Tx Packets: {device[9]}")
            # Add more fields if your model provides them.
    except Exception as e:
        print("Error parsing HTML device list:", e)
        print("Raw HTML response was:")
        print(html_text)

if __name__ == "__main__":
    session, final_url, resp_text = login()
    if session:
        token = extract_token_from_url(final_url)
        if not token:
            token = extract_token_from_response(resp_text)
            if not token:
                token = parse_response(resp_text)
        if token:
            index_url = f"{ROUTER_URL}/{token}/userRpm/Index.htm"
            response = session.get(index_url)
            if response.ok:
                print_connected_devices(session, token)
            else:
                print("Failed to access Index page.")
        else:
            print("Session token not found in login response or URL.")