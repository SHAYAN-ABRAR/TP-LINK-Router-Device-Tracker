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
    session.cookies.set("Authorization", auth_cookie, path="/", domain="192.168.100.108")
    login_url = ROUTER_URL + LOGIN_PATH
    params = {"Save": "Save"}
    resp = session.get(login_url, params=params, allow_redirects=True)
    if resp.status_code == 200:
        print("Login successful.")
        return session, resp.url, resp.text
    else:
        print(f"Login failed with status code: {resp.status_code}")
        print("Response:", resp.text)
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
        print("No URL found in response")
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
    # Fetch the JSON endpoint for wireless clients
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
    # Retry the request up to 2 times if it fails
    for attempt in range(3):
        try:
            response = session.get(status_url, headers=headers, timeout=10)
            if response.status_code == 200:
                print("\n--- RAW RESPONSE FROM ROUTER (JSON) ---")
                print(response.text)
                print("--- END RAW RESPONSE ---\n")
                return response.text
            else:
                print(f"JSON request failed with status code: {response.status_code}")
                print("Response:", response.text)
        except requests.exceptions.RequestException as e:
            print(f"JSON request error on attempt {attempt + 1}: {e}")
        time.sleep(1)  # Wait before retrying
    print("Failed to retrieve JSON data after retries.")
    return None

def retrieve_wireless_clients_html(session, token, page=1, vap_idx=0):
    # Add 500ms delay before scraping
    time.sleep(0.5)
    # Fetch the HTML endpoint for wireless stations with query parameters
    status_url = f"{ROUTER_URL}/{token}/userRpm/WlanStationRpm.htm?Page={page}&vapIdx={vap_idx}"
    headers = {
        "Referer": f"{ROUTER_URL}/{token}/userRpm/Index.htm",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    }
    try:
        response = session.get(status_url, headers=headers, timeout=10)
        print(f"\n--- RAW RESPONSE FROM ROUTER (HTML, Page={page}, vapIdx={vap_idx}) ---")
        print(response.text)
        print("--- END RAW RESPONSE ---\n")
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"HTML request error (vapIdx={vap_idx}, Page={page}): {e}")
        return None

def print_connected_devices(session, token):
    # Try the JSON approach first
    json_text = retrieve_wireless_devices(session, token)
    if json_text:
        try:
            data = json.loads(json_text)
            devices = []
            # Check for the expected structure: {"success": true, "timeout": false, "data": [...]}
            if (isinstance(data, dict) and data.get('success') and not data.get('timeout') and
                'data' in data and isinstance(data['data'], list)):
                devices = data['data']
            else:
                print("JSON response does not match expected format.")
                print("Raw JSON:", json_text)
            
            if devices:
                print(f"Total connected devices (from JSON): {len(devices)}")
                for idx, device in enumerate(devices, 1):
                    mac = device.get('mac_addr', device.get('mac', device.get('MAC', 'N/A')))
                    ip = device.get('ip_addr', device.get('ip', 'N/A'))
                    name = device.get('name', device.get('hostname', device.get('hostName', 'N/A')))
                    print(f"{idx}. Details:")
                    print(f"   MAC: {mac}")
                    print(f"   IP: {ip}")
                    print(f"   Name: {name}")
                return  # Exit if JSON succeeds
            else:
                print("No device list found in JSON response.")
        except Exception as e:
            print("Error parsing JSON:", e)
            print("Raw JSON response was:")
            print(json_text)

    # Fallback to HTML scraping if JSON fails
    devices = []
    wlan_status_map = {
        0: "STA-AUTH",
        1: "STA-ASSOC",
        2: "WPA",
        3: "WPA-PSK",
        4: "WPA2",
        5: "WPA2-PSK",
        6: "802_1X",
        7: "STA-JOINED",
        8: "AP-UP",
        9: "AP-DOWN",
        10: "Disconnected"
    }
    vap_idx = 0  # Single SSID based on wlanHostPara[8] = 0
    page = 1
    while True:
        html_text = retrieve_wireless_clients_html(session, token, page=page, vap_idx=vap_idx)
        if not html_text:
            print(f"No data received from HTML endpoint (vapIdx={vap_idx}, Page={page}).")
            break

        try:
            # Extract the embedded hostList array from the HTML
            match = re.search(r'var hostList = new Array\(\s*(.*?)\s*\);', html_text, re.DOTALL)
            if not match:
                print(f"Could not find hostList in HTML response (vapIdx={vap_idx}, Page={page}).")
                break

            array_str = match.group(1).strip()
            elements = re.findall(r'"([^"]*)"|(\d+)', array_str)
            elements = [e[0] if e[0] else e[1] for e in elements]

            # Extract wlanHostPara for pagination info
            para_match = re.search(r'var wlanHostPara = new Array\(\s*(.*?)\s*\);', html_text, re.DOTALL)
            total_devices = 0
            devices_per_page = 8
            field_count = 5
            if para_match:
                para_elements = re.findall(r'(\d+)', para_match.group(1))
                total_devices = int(para_elements[0]) if para_elements else 0
                devices_per_page = int(para_elements[2]) if len(para_elements) > 2 else 8
                field_count = int(para_elements[4]) if len(para_elements) > 4 else 5

            # Devices are grouped in fixed-length tuples (5 fields per device)
            page_devices = [elements[i:i+field_count] for i in range(0, len(elements), field_count) if len(elements[i:i+field_count]) == field_count]
            
            if not page_devices:
                print(f"No more devices found on vapIdx={vap_idx}, Page={page}.")
                break

            devices.extend(page_devices)
            if len(devices) >= total_devices:
                break
            page += 1
        except Exception as e:
            print(f"Error parsing HTML device list (vapIdx={vap_idx}, Page={page}):", e)
            print("Raw HTML response was:")
            print(html_text)
            break

    if devices:
        print(f"Total connected wireless devices (from HTML): {len(devices)}")
        for idx, device in enumerate(devices, 1):
            status = wlan_status_map.get(int(device[1]), "Unknown") if len(device) > 1 else "N/A"
            print(f"{idx}. Details:")
            print(f"   MAC: {device[0] if len(device) > 0 else 'N/A'}")
            print(f"   Current Status: {status}")
            print(f"   Received Packets: {device[2] if len(device) > 2 else 'N/A'}")
            print(f"   Sent Packets: {device[3] if len(device) > 3 else 'N/A'}")
            print(f"   Config Flag: {device[4] if len(device) > 4 else 'N/A'}")
            print("   Note: IP address and device name not available in HTML response. Please check the JSON endpoint.")
    else:
        print("No devices found in HTML response.")
        print("The JSON endpoint is required for IP address and device name. Verify the URL: http://192.168.100.108/{token}/data/map_access_wireless_client_grid.json")
        print("Ensure you are logged in and the session token is valid. Test the endpoint in a browser after logging into the router.")

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
                print(f"Failed to access Index page: {response.status_code}")
                print("Response:", response.text)
        else:
            print("Session token not found in login response or URL.")