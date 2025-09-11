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
    return text.strip().replace('\n', '').replace('\t', '') if text else 'Not Found'

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
            array_values = []
            for v in values:
                v_clean = re.sub(r'^["\']|["\']$', '', v.strip())  # Remove surrounding quotes
                array_values.append(clean_text(v_clean))
            data_arrays[array_name] = array_values
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
        table = soup_dhcp.find('table')
        if table:
            rows = table.find_all('tr')[1:]  # Skip header row
            for row in rows:
                cells = row.find_all('td')
                if len(cells) >= 4:  # Expecting ID, Client Name, MAC, IP, Lease Time
                    device = {
                        'IP Address': clean_text(cells[3].text),  # Assigned IP (index 3)
                        'MAC Address': clean_text(cells[2].text),  # MAC Address (index 2)
                        'Device Name': clean_text(cells[1].text),  # Client Name (index 1)
                        'Lease Time': clean_text(cells[4].text) if len(cells) > 4 else 'Not Found'
                    }
                    # Only add if at least one field has data
                    if any(value != 'Not Found' for value in device.values()):
                        router_info['Connected Devices'].append(device)

        # Print router information
        for section, data in router_info.items():
            if isinstance(data, dict):
                print(f"\n**{section}**")
                for key, value in data.items():
                    print(f"{key}: {value}")
            elif isinstance(data, list) and section == 'Connected Devices':
                print(f"\n**{section}**")
                if data:
                    print("| IP Address | MAC Address | Device Name | Lease Time |")
                    print("|------------|-------------|-------------|------------|")
                    for device in data:
                        print(f"| {device['IP Address']} | {device['MAC Address']} | {device['Device Name']} | {device['Lease Time']} |")
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