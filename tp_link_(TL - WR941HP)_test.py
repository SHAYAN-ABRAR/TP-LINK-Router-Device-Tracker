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
    """Generate MD5 hash of the input text."""
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def get_auth_cookie(username, password, use_md5=True):
    """Generate Basic Authentication cookie."""
    if use_md5:
        password = md5_hash(password)
    auth_str = f"{username}:{password}"
    b64_auth = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
    return f"Basic {b64_auth}"

def login():
    """Log in to the router and return session, final URL, and response text."""
    session = requests.Session()
    auth_cookie = get_auth_cookie(USERNAME, PASSWORD, use_md5=True)
    session.cookies.set("Authorization", auth_cookie, path="/", domain="192.168.100.108")
    login_url = ROUTER_URL + LOGIN_PATH
    params = {"Save": "Save"}
    try:
        resp = session.get(login_url, params=params, allow_redirects=True)
        if resp.status_code == 200:
            return session, resp.url, resp.text
        else:
            return None, None, None
    except requests.exceptions.RequestException:
        return None, None, None

def extract_token_from_response(resp_text):
    """Extract session token from response text."""
    match = re.search(r'/([A-Za-z0-9]+)/userRpm/Index\.htm', resp_text)
    if match:
        return match.group(1)
    return None

def extract_token_from_url(url):
    """Extract session token from URL."""
    match = re.search(r'/([A-Za-z0-9]+)/userRpm/Index\.htm', url)
    if match:
        return match.group(1)
    return None

def parse_response(resp_text):
    """Parse response text to extract token from href."""
    match = re.search(r'href\s*=\s*"([^"]+)"', resp_text)
    if match:
        url = match.group(1)
        path_parts = urlparse(url).path.strip("/").split("/")
        if len(path_parts) >= 2:
            return path_parts[0]
    return None

def retrieve_dhcp_clients(session, token):
    """Retrieve DHCP clients list."""
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
    """Retrieve wireless clients HTML."""
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

def retrieve_router_status(session, token):
    """Retrieve router status HTML."""
    time.sleep(0.5)
    status_url = f"{ROUTER_URL}/{token}/userRpm/StatusRpm.htm"
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

def print_connected_devices_and_status(session, token):
    """Print connected devices and router status."""
    # Fetch wireless MACs
    wireless_macs = set()
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

    # Fetch and parse DHCP clients
    dhcp_text = retrieve_dhcp_clients(session, token)
    devices = []
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
                    for dev in dhcp_devices if not wireless_macs or dev[1].lower() in wireless_macs
                ]
                
                if devices:
                    print(f"Total connected wireless devices (from DHCP): {len(devices)}")
                    for idx, device in enumerate(devices, 1):
                        print(f"{idx}. Details:")
                        print(f"   HOST NAME: {device['name']}")
                        print(f"   MAC ADDRESS: {device['mac_addr']}")
                        print(f"   IP ADDRESS: {device['ip_addr']}")
                        print(f"   LEASE TIME: {device['lease_time']}")
        except Exception:
            pass

    # Fetch and parse router status
    status_text = retrieve_router_status(session, token)
    if status_text:
        try:
            print("\nRouter Status Information:")
            
            # Initialize dictionaries for storing parsed information
            lan_info = {}
            wan_info = {}
            wireless_info = {}
            sys_info = {}
            traffic_info = {}
            
            # Parse lanPara
            lan_match = re.search(r'var lanPara = new Array\((.*?)\);', status_text, re.DOTALL)
            if lan_match:
                lan_elements = re.findall(r'"([^"]*)"|(\d+)', lan_match.group(1))
                lan_elements = [e[0] if e[0] else e[1] for e in lan_elements]
                lan_info = {
                    "mac_address": lan_elements[0] if len(lan_elements) > 0 else "N/A",
                    "ip_address": lan_elements[1] if len(lan_elements) > 1 else "N/A",
                    "subnet_mask": lan_elements[2] if len(lan_elements) > 2 else "N/A"
                }
            
            # Parse wanPara
            wan_match = re.search(r'var wanPara = new Array\((.*?)\);', status_text, re.DOTALL)
            if wan_match:
                wan_elements = re.findall(r'"([^"]*)"|(\d+)', wan_match.group(1))
                wan_elements = [e[0] if e[0] else e[1] for e in wan_elements]
                # Connection type: 4 corresponds to Dynamic IP as per user-provided mapping
                connection_type = "Dynamic IP" if wan_elements[0] == "4" else "N/A"
                wan_info = {
                    "mac_address": wan_elements[1] if len(wan_elements) > 1 else "N/A",
                    "ip_address": wan_elements[2] if len(wan_elements) > 2 else "N/A",
                    "subnet_mask": wan_elements[4] if len(wan_elements) > 4 else "N/A",
                    "gateway": wan_elements[7] if len(wan_elements) > 7 else "N/A",
                    "dns": wan_elements[11] if len(wan_elements) > 11 else "N/A",
                    "connection_type": connection_type
                }
            
            # Parse wlanPara
            wlan_match = re.search(r'var wlanPara = new Array\((.*?)\);', status_text, re.DOTALL)
            if wlan_match:
                wlan_elements = re.findall(r'"([^"]*)"|(\d+)', wlan_match.group(1))
                wlan_elements = [e[0] if e[0] else e[1] for e in wlan_elements]
                ssids = [wlan_elements[1]] if len(wlan_elements) > 1 and wlan_elements[1] else []
                if len(wlan_elements) > 11 and wlan_elements[11]:
                    ssids.append(wlan_elements[11])
                wireless_info = {
                    "ssid": ", ".join(ssids) if ssids else "N/A"
                }
            
            # Parse statusPara
            status_match = re.search(r'var statusPara = new Array\((.*?)\);', status_text, re.DOTALL)
            if status_match:
                status_elements = re.findall(r'"([^"]*)"|(\d+)', status_match.group(1))
                status_elements = [e[0] if e[0] else e[1] for e in status_elements]
                sys_info = {
                    "firmware_version": status_elements[5] if len(status_elements) > 5 else "N/A",
                    "hardware_version": status_elements[6] if len(status_elements) > 6 else "N/A"
                }
            
            # Parse statistList
            stat_match = re.search(r'var statistList = new Array\((.*?)\);', status_text, re.DOTALL)
            if stat_match:
                stat_elements = re.findall(r'"([^"]*)"|(\d+)', stat_match.group(1))
                stat_elements = [e[0] if e[0] else e[1] for e in stat_elements]
                traffic_info = {
                    "bytes_received": stat_elements[0] if len(stat_elements) > 0 else "N/A",
                    "bytes_sent": stat_elements[1] if len(stat_elements) > 1 else "N/A",
                    "packets_received": stat_elements[2] if len(stat_elements) > 2 else "N/A",
                    "packets_sent": stat_elements[3] if len(stat_elements) > 3 else "N/A"
                }
            
            # Print parsed information
            print("  LAN:")
            print(f"    MAC Address: {lan_info.get('mac_address', 'N/A')}")
            print(f"    IP Address: {lan_info.get('ip_address', 'N/A')}")
            print(f"    Subnet Mask: {lan_info.get('subnet_mask', 'N/A')}")
            
            print("  WAN:")
            print(f"    MAC Address: {wan_info.get('mac_address', 'N/A')}")
            print(f"    IP Address: {wan_info.get('ip_address', 'N/A')}")
            print(f"    Subnet Mask: {wan_info.get('subnet_mask', 'N/A')}")
            print(f"    Gateway: {wan_info.get('gateway', 'N/A')}")
            print(f"    DNS: {wan_info.get('dns', 'N/A')}")
            print(f"    Connection Type: {wan_info.get('connection_type', 'N/A')}")
            
            print("  Wireless:")
            print(f"    Name (SSID): {wireless_info.get('ssid', 'N/A')}")
            
            print("  System:")
            print(f"    Firmware Version: {sys_info.get('firmware_version', 'N/A')}")
            print(f"    Hardware Version: {sys_info.get('hardware_version', 'N/A')}")
            
            print("  Traffic Statistics:")
            print(f"    Bytes received: {traffic_info.get('bytes_received', 'N/A')}")
            print(f"    Bytes sent: {traffic_info.get('bytes_sent', 'N/A')}")
            print(f"    Packets received: {traffic_info.get('packets_received', 'N/A')}")
            print(f"    Packets sent: {traffic_info.get('packets_sent', 'N/A')}")
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
                print_connected_devices_and_status(session, token)