import os
import logging
import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

def clean_text(text):
    """Clean text by stripping whitespace and replacing special characters."""
    cleaned = text.strip().replace('\n', '').replace('\t', '') if text else 'Not Found'
    return 'Not Found' if cleaned in ['', '0'] else cleaned  # Treat empty or '0' as Not Found

def scrape_router_info(status_url, dhcp_url):
    """
    Scrapes router information from a TP-Link TL-WR802N emulator's status and DHCP client list pages.

    Args:
        status_url (str): The URL of the router's status page.
        dhcp_url (str): The URL of the DHCP client list page.

    Returns:
        dict: A dictionary containing router information for Internet, LAN, Wireless, and Connected Devices,
              or None if an error occurs.
    """
    try:
        # Validate URLs
        for url in [status_url, dhcp_url]:
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                logger.error(f"Invalid URL provided: {url}")
                return None

        # Fetch status HTML content dynamically
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response_status = requests.get(status_url, headers=headers, timeout=10)
        response_status.raise_for_status()
        html_status = response_status.text

        # Save raw status HTML for debugging
        with open("fetched_status.html", "w", encoding="utf-8") as f:
            f.write(html_status)
        logger.info(f"Fetched status HTML saved to fetched_status.html (length: {len(html_status)} bytes)")

        # Fetch DHCP client list HTML content dynamically
        response_dhcp = requests.get(dhcp_url, headers=headers, timeout=10)
        response_dhcp.raise_for_status()
        html_dhcp = response_dhcp.text

        # Save raw DHCP HTML for debugging
        with open("fetched_dhcp.html", "w", encoding="utf-8") as f:
            f.write(html_dhcp)
        logger.info(f"Fetched DHCP HTML saved to fetched_dhcp.html (length: {len(html_dhcp)} bytes)")

        # Extract JavaScript arrays from status page
        scripts_status = re.findall(r'var\s+(\w+Para)\s*=\s*new\s+Array\s*\((.*?)\);', html_status, re.DOTALL)

        data_arrays = {}
        for match in scripts_status:
            array_name = match[0]
            array_values_str = match[1]
            values = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', array_values_str)
            array_values = [re.sub(r'^["\']|["\']$', '', v.strip()) for v in values]
            data_arrays[array_name] = [clean_text(val) for val in array_values]
        logger.info(f"Extracted arrays from status page: {list(data_arrays.keys())}")

        # Initialize dictionary with router model name in Internet section
        router_info = {
            'Internet': {'Model': 'TP-LINK TL-WR802N'},
            'LAN': {},
            'Wireless': {},
            'Connected Devices': []
        }

        # Map data to sections based on array indices from status page
        if 'statusPara' in data_arrays and len(data_arrays['statusPara']) > 6:
            status_data = data_arrays['statusPara']
            router_info['Internet']['Firmware Version'] = status_data[5]
            router_info['Internet']['Hardware Version'] = status_data[6]

        if 'lanPara' in data_arrays and len(data_arrays['lanPara']) > 2:
            lan_data = data_arrays['lanPara']
            router_info['LAN']['MAC Address'] = lan_data[0]
            router_info['LAN']['IP Address'] = lan_data[1]
            router_info['LAN']['Subnet Mask'] = lan_data[2]

        if 'wlanPara' in data_arrays and len(data_arrays['wlanPara']) > 11:
            wlan_data = data_arrays['wlanPara']
            router_info['Wireless']['Wireless Radio'] = 'Disabled' if wlan_data[0] == '0' else 'Enabled'
            router_info['Wireless']['Name (SSID)'] = wlan_data[1]
            router_info['Wireless']['Channel'] = 'Auto (Current channel 0)' if wlan_data[2] == '0' else wlan_data[2]
            router_info['Wireless']['Mode'] = '11bgn mixed' if wlan_data[3] == '5' else 'Not Found'
            router_info['Wireless']['Channel Width'] = 'Automatic'
            router_info['Wireless']['MAC Address'] = wlan_data[4]
            router_info['Wireless']['WDS Status'] = 'Disabled' if wlan_data[10] == '0' else 'Enabled'

        # Parse DHCP client list for Connected Devices
        soup_dhcp = BeautifulSoup(html_dhcp, 'html.parser')
        tables = soup_dhcp.find_all('table')
        logger.info(f"Found {len(tables)} tables in DHCP page")

        if tables:
            for table in tables:
                rows = table.find_all('tr')
                logger.info(f"Found {len(rows)} rows in a DHCP table")
                # Try to detect header to determine column order
                header_row = rows[0] if rows and rows[0].find_all('th') else None
                headers = [clean_text(th.text) for th in header_row.find_all('th')] if header_row else []
                logger.info(f"Detected headers: {headers}")

                for i, row in enumerate(rows[1:], 1):  # Skip header row, start from 1
                    cells = row.find_all('td')
                    if len(cells) >= 4:  # Expecting at least Client Name, IP, MAC, Lease Time
                        # Adjust indexing based on observed pattern: [Client Name, IP, MAC, Lease]
                        device = {
                            'Device Name': clean_text(cells[0].text) if len(cells) > 0 else 'Not Found',
                            'IP Address': clean_text(cells[1].text) if len(cells) > 1 else 'Not Found',
                            'MAC Address': clean_text(cells[2].text) if len(cells) > 2 else 'Not Found',
                            'Lease Time': clean_text(cells[3].text) if len(cells) > 3 else 'Not Found'
                        }
                        # Filter out devices with all fields as Not Found or invalid
                        if not all(value in ['Not Found', ''] for value in device.values()):
                            router_info['Connected Devices'].append(device)

        # Fallback to JS arrays in DHCP page if table parsing fails
        dhcp_scripts = re.findall(r'var\s+(\w+List|dhcpPara)\s*=\s*new\s+Array\s*\((.*?)\);', html_dhcp, re.DOTALL)
        if dhcp_scripts and not router_info['Connected Devices']:
            logger.info(f"Found DHCP JS arrays: {dhcp_scripts[0][0] if dhcp_scripts else 'None'}")
            for match in dhcp_scripts:
                array_name = match[0]
                array_values_str = match[1]
                values = re.split(r',\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', array_values_str)
                array_values = [re.sub(r'^["\']|["\']$', '', v.strip()) for v in values]
                # Assume pattern: Client Name, IP, MAC, Lease
                for j in range(0, len(array_values), 4):
                    device = {
                        'Device Name': clean_text(array_values[j]) if j < len(array_values) else 'Not Found',
                        'IP Address': clean_text(array_values[j + 1]) if j + 1 < len(array_values) else 'Not Found',
                        'MAC Address': clean_text(array_values[j + 2]) if j + 2 < len(array_values) else 'Not Found',
                        'Lease Time': clean_text(array_values[j + 3]) if j + 3 < len(array_values) else 'Not Found'
                    }
                    if not all(value in ['Not Found', ''] for value in device.values()):
                        router_info['Connected Devices'].append(device)

        # Print router information with requested format for Connected Devices
        for section, data in router_info.items():
            if isinstance(data, dict):
                print(f"\n**{section}**")
                for key, value in data.items():
                    print(f"{key}: {value}")
            elif isinstance(data, list) and section == 'Connected Devices':
                print(f"\n**{section}**")
                if data:
                    for i, device in enumerate(data, 1):
                        print(f"{i}. Client name: {device.get('Device Name', 'Unknown')}")
                        print(f"   MAC Address: {device.get('MAC Address', 'Not Found')}")
                        print(f"   IP Address: {device.get('IP Address', 'Not Found')}")
                        print(f"   Lease Time: {device.get('Lease Time', 'Not Found')}")
                else:
                    print("No connected devices found")

        return router_info

    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching URL: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Error scraping HTML content: {str(e)}", exc_info=True)
        return None

# Example usage for TL-WR802N
status_url = "https://emulator.tp-link.com/TL-WR802N_V1/userRpm/StatusRpm.htm"
dhcp_url = "https://emulator.tp-link.com/TL-WR802N_V1/userRpm/AssignedIpAddrListRpm.htm?Refresh=Refresh"
scrape_router_info(status_url, dhcp_url)