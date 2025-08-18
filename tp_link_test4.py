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

def retrieve_router_status(session, token):
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
                
                # Filter DHCP devices against wireless MACs; if no wireless MACs, include all
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
            
            # Extract all JavaScript variables (arrays or single values)
            arrays = re.findall(r'var (\w+) = new Array\((.*?)\);|var (\w+) = "([^"]*)";|var (\w+) = (\d+);', status_text, re.DOTALL)
            lan_info = {}
            wan_info = {}
            wireless_info = {}
            sys_info = {}
            traffic_info = {}
            
            for array in arrays:
                if array[0]:  # Array match: var name, array content
                    var_name, array_content = array[0], array[1]
                    elements = re.findall(r'"([^"]*)"|(\d+)', array_content)
                    elements = [e[0] if e[0] else e[1] for e in elements]
                elif array[2]:  # String value match: var name, value
                    var_name, elements = array[2], [array[3]]
                else:  # Numeric value match: var name, value
                    var_name, elements = array[4], [array[5]]
                
                var_lower = var_name.lower()
                if 'lan' in var_lower or 'lanCfg' in var_lower or 'laninfo' in var_lower:
                    lan_info = {
                        "mac_address": elements[0] if len(elements) > 0 else "N/A",
                        "ip_address": elements[1] if len(elements) > 1 else "192.168.0.1",
                        "subnet_mask": elements[2] if len(elements) > 2 else "255.255.255.0"
                    }
                elif 'wan' in var_lower or 'wanCfg' in var_lower or 'waninfo' in var_lower:
                    wan_info = {
                        "ip_address": elements[0] if len(elements) > 0 else "N/A",
                        "subnet_mask": elements[1] if len(elements) > 1 else "N/A",
                        "gateway": elements[2] if len(elements) > 2 else "N/A",
                        "dns": elements[3] if len(elements) > 3 else "N/A",
                        "connection_type": elements[4] if len(elements) > 4 else "N/A"
                    }
                elif 'wireless' in var_lower or 'ssid' in var_lower or 'wlan' in var_lower or 'wlanCfg' in var_lower:
                    wireless_info = {
                        "ssid": elements[0] if len(elements) > 0 else "N/A"
                    }
                elif 'sys' in var_lower or 'system' in var_lower or 'firmware' in var_lower or 'hardware' in var_lower or 'uptime' in var_lower or 'sysCfg' in var_lower:
                    sys_info.update({
                        "firmware_version": elements[0] if len(elements) > 0 and ('firmware' in var_lower or 'sys' in var_lower or 'sysCfg' in var_lower) else sys_info.get('firmware_version', "N/A"),
                        "hardware_version": elements[0] if len(elements) > 0 and 'hardware' in var_lower else sys_info.get('hardware_version', "N/A"),
                        "uptime": elements[0] if len(elements) > 0 and 'uptime' in var_lower else sys_info.get('uptime', "N/A")
                    })
                elif 'traffic' in var_lower or 'stat' in var_lower or 'statistic' in var_lower:
                    traffic_info = {
                        "bytes_received": elements[0] if len(elements) > 0 else "N/A",
                        "bytes_sent": elements[1] if len(elements) > 1 else "N/A",
                        "packets_received": elements[2] if len(elements) > 2 else "N/A",
                        "packets_sent": elements[3] if len(elements) > 3 else "N/A"
                    }
            
            # Print LAN Info
            print("  LAN:")
            print(f"    MAC Address: {lan_info.get('mac_address', 'N/A')}")
            print(f"    IP Address: {lan_info.get('ip_address', '192.168.0.1')}")
            print(f"    Subnet Mask: {lan_info.get('subnet_mask', '255.255.255.0')}")
            
            # Print WAN Info
            print("  WAN:")
            print(f"    IP Address: {wan_info.get('ip_address', 'N/A')}")
            print(f"    Subnet Mask: {wan_info.get('subnet_mask', 'N/A')}")
            print(f"    Gateway: {wan_info.get('gateway', 'N/A')}")
            print(f"    DNS: {wan_info.get('dns', 'N/A')}")
            print(f"    Connection Type: {wan_info.get('connection_type', 'N/A')}")
            
            # Print Wireless Info
            print("  Wireless:")
            print(f"    Name (SSID): {wireless_info.get('ssid', 'N/A')}")
            
            # Print System Info
            print("  System:")
            print(f"    Firmware Version: {sys_info.get('firmware_version', 'N/A')}")
            print(f"    Hardware Version: {sys_info.get('hardware_version', 'N/A')}")
            print(f"    Uptime: {sys_info.get('uptime', 'N/A')}")
            
            # Print Traffic Statistics
            print("Traffic Statistics:")
            print(f"  Bytes received: {traffic_info.get('bytes_received', 'N/A')}")
            print(f"  Bytes sent: {traffic_info.get('bytes_sent', 'N/A')}")
            print(f"  Packets received: {traffic_info.get('packets_received', 'N/A')}")
            print(f"  Packets sent: {traffic_info.get('packets_sent', 'N/A')}")
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