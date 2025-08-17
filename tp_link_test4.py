import requests
import hashlib
import base64
from urllib.parse import urlparse
import re
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
        return session, resp.url, resp.text
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
        return None
    path_parts = urlparse(url).path.strip("/").split("/")
    if len(path_parts) >= 2:
        return path_parts[0]
    return None

def retrieve_dhcp_clients(session, token):
    time.sleep(0.5)
    status_url = f"{ROUTER_URL}/{token}/userRpm/AssignedIpAddrListRpm.htm"
    headers = {
        "Referer": f"{ROUTER_URL}/{token}/userRpm/Index.htm",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    }
    try:
        response = session.get(status_url, headers=headers, timeout=10)
        return response.text
    except requests.exceptions.RequestException:
        return None

def retrieve_wireless_clients_html(session, token, page=1, vap_idx=0):
    time.sleep(0.5)
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
        return response.text
    except requests.exceptions.RequestException:
        return None

def print_connected_devices(session, token):
    dhcp_text = retrieve_dhcp_clients(session, token)
    wireless_macs = set()
    devices = []
    
    html_text = retrieve_wireless_clients_html(session, token, page=1, vap_idx=0)
    if html_text:
        try:
            match = re.search(r'var hostList = new Array(\s*(.*?)\s*);', html_text, re.DOTALL)
            if match:
                array_str = match.group(1).strip()
                elements = re.findall(r'"([^"]*)"|(\d+)', array_str)
                elements = [e[0] if e[0] else e[1] for e in elements]
                field_count = 5
                html_devices = [elements[i:i+field_count] for i in range(0, len(elements), field_count) if len(elements[i:i+field_count]) == field_count]
                wireless_macs = {device[0].lower() for device in html_devices}
        except Exception:
            pass
    
    if dhcp_text:
        try:
            match = re.search(r'var DHCPDynList = new Array(\s*(.*?)\s*);', dhcp_text, re.DOTALL)
            if match:
                array_str = match.group(1).strip()
                elements = re.findall(r'"([^"]*)"', array_str)
                field_count = 4
                dhcp_devices = [elements[i:i+field_count] for i in range(0, len(elements), field_count) if len(elements[i:i+field_count]) == field_count]
                
                devices = [
                    {"name": dev[0], "mac_addr": dev[1], "ip_addr": dev[2], "lease_time": dev[3]}
                    for dev in dhcp_devices if dev[1].lower() in wireless_macs
                ]
                
                if devices:
                    print(f"Total connected wireless devices (from DHCP): {len(devices)}")
                    for idx, device in enumerate(devices, 1):
                        print(f"{idx}. Details:")
                        print(f"   HOST NAME: {device['name']}")
                        print(f"   MAC ADDRESS: {device['mac_addr']}")
                        print(f"   IP ADDRESS: {device['ip_addr']}")
                        print(f"   LEASE TIME: {device['lease_time']}")
                    return
        except Exception:
            pass

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