import requests
import hashlib
import base64
from urllib.parse import urlparse
import re
import urllib.parse

ROUTER_URL = "http://192.168.100.108"
LOGIN_PATH = "/userRpm/LoginRpm.htm"
USERNAME = "admin"  # Replace with your username
PASSWORD = "admin"  # Replace with your password
REFERER = ""
COOKIE = ""

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
    # Try to find the token in the response HTML
    # Example: look for a URL like /WKIDTSRCGPKWCIMA/userRpm/Index.htm
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
    print("parse_response resp_text : ",resp_text)
    match = re.search(r'href\s*=\s*"([^"]+)"', resp_text)
    
    if match:
        url = match.group(1)
        print(url)  # Output: http://192.168.100.108/UYJKXMLAJHJWXURC/userRpm/Index.htm
    else:
        print("No URL found")
    path_parts = urlparse(url).path.strip("/").split("/")
    print("parse_response path_parts : ",path_parts)
    print("parse_response path_parts length : ",len(path_parts))
    if len(path_parts) >= 2:
        second_param = path_parts[0]
        print(second_param)  # Output: userRpm
        return second_param
    else:
        print("URL does not have a second path segment")
        return None

def retrieve_wireless_devices(session, token):
    #Access the connected devices page userRpm/BasicNetworkMapRpm.htm
    print("token 3.1 : ",token)
    status_url = f"{ROUTER_URL}/{token}/data/map_access_wireless_client_grid.json"
    referer_url = f"{ROUTER_URL}/{token}/userRpm/Index.htm"
    # auth_cookie = get_auth_cookie(USERNAME, PASSWORD, use_md5=True)
    #auth_cookie_encoded = urllib.parse.quote(get_auth_cookie(USERNAME, PASSWORD, use_md5=True))
    #print("Session Cookies:",     auth_cookie_encoded)
    #print("auth_cookie_encoded : ",auth_cookie_encoded)
    #session.cookies.set("Authorization", auth_cookie_encoded, path="/")
    headers = {
        "Referer": f"{ROUTER_URL}/{token}/userRpm/BasicNetworkMapRpm.htm",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Origin": ROUTER_URL,
        "X-Requested-With": "XMLHttpRequest"
    }
    print("Request URL:", status_url)
    print("Request Headers:", headers)
    print("Session Cookies:", session.cookies.get_dict())
    response = session.get(status_url, headers=headers)
    if response.ok:
        print("Connected devices retrieved successfully.")
        print("retrieve_wireless_devices response ",response.text)
        return response.text
    else:
        print("Failed to retrieve connected devices.")
        print("Status code:", response.status_code)
        print("Response:", response.text)
        return None

def get_wireless_connected_devices(self):
        """
        Returns the details of devices connected wireless

        >>> all_connected_devices = tp_client.get_wireless_connected_devices()
        >>> print(all_connected_devices)
        Output
        -------
        [
            {
                'associatedDeviceMACAddress': 'a7:ea:b4:c0:1b:e8',
                'X_TP_TotalPacketsSent': '328263',
                'X_TP_TotalPacketsReceived': '52826',
                'X_TP_HostName': 'wlan0'
            }
        ]

        :return: Python list with dict each representing individual user
        """
        url = "http://" + self.router_url + "/cgi?6"
        payload = "[LAN_WLAN_ASSOC_DEV#0,0,0,0,0,0#1,1,0,0,0,0]0," \
                  "4\r\nAssociatedDeviceMACAddress\r\nX_TP_TotalPacketsSent\r\nX_TP_TotalPacketsReceived\r" \
                  "\nX_TP_HostName\r\n "
        headers = self.AUTH_HEADER
        response = requests.post(url, headers=headers, data=payload).text
        regex = (r"(?i)(?:associatedDeviceMACAddress=(?P<associatedDeviceMACAddress>\S+)\n"
                 r"X_TP_TotalPacketsSent=(?P<X_TP_TotalPacketsSent>\S+)\n"
                 r"X_TP_TotalPacketsReceived=(?P<X_TP_TotalPacketsReceived>\S+)\n"
                 r"X_TP_HostName=(?P<X_TP_HostName>\S+)\n"
                 r")")
        connected_devices = []
        for each_device_data in re.findall(regex, response, re.MULTILINE):
            connected_devices.append(dict(zip(['associatedDeviceMACAddress',
                                               'X_TP_TotalPacketsSent',
                                               'X_TP_TotalPacketsReceived',
                                               'X_TP_HostName'], each_device_data)))
        return connected_devices

if __name__ == "__main__":
    session, final_url, resp_text = login()
    if session:
        token = extract_token_from_url(final_url)
        if not token:
            # Try extracting from response text as fallback
            print("resp_text : ",resp_text)
            token = extract_token_from_response(resp_text)
            print("token 1 : ",token)
            token = extract_token_from_response(resp_text)
            print("token 2 : ",token)
            token = parse_response(resp_text)
            print("token 3 : ",token)
        if token:
            index_url = f"{ROUTER_URL}/{token}/userRpm/Index.htm"
            REFERER = index_url
            print("parse_response REFERER : ",REFERER)
            print("userRpm/Index.htm Session Cookies:", session.cookies.get_dict())
            response = session.get(index_url)
            if response.ok:
                print("Redirected and accessed Index page successfully.")
                print(response.text)

                retrieve_wireless_devices(session, token)
            else:
                print("Failed to access Index page.")

        else:
            print("Session token not found in login response or URL.")