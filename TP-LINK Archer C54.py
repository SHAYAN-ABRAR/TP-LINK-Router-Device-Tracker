import os
import logging
import time
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
USERNAME = os.getenv("ROUTER_USERNAME", "admin")
PASSWORD = os.getenv("ROUTER_PASSWORD", "admin")

def clean_text(text):
    """Clean text by stripping whitespace and replacing special characters."""
    return text.strip().replace('\n', '').replace('\t', '') if text else 'Not Found'

def scrape_router_info(network_status_url, network_map_url):
    """
    Scrapes router information from a TP-Link emulator's network status page and
    connected devices from the network map page.

    Args:
        network_status_url (str): The URL of the router's network status page.
        network_map_url (str): The URL of the router's network map page.

    Returns:
        dict: A dictionary containing router information for Internet, LAN,
              DHCP Server, Dynamic DNS, and Connected Devices, or None if
              an error occurs.
    """
    try:
        # Validate URLs
        for url in [network_status_url, network_map_url]:
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                logger.error(f"Invalid URL provided: {url}")
                return None

        # Set up Selenium
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        driver = webdriver.Chrome(options=chrome_options)
        logger.info(f"Navigating to {network_status_url}")
        driver.get(network_status_url)

        # Attempt login
        try:
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.ID, "userName"))
            )
            username_field = driver.find_element(By.ID, "userName")
            password_field = driver.find_element(By.ID, "pcPassword")
            login_button = driver.find_element(By.ID, "loginBtn")
            username_field.send_keys(USERNAME)
            password_field.send_keys(PASSWORD)
            login_button.click()
            logger.info("Logged in successfully")
            WebDriverWait(driver, 10).until(
                EC.invisibility_of_element_located((By.ID, "loginBtn"))
            )
        except TimeoutException:
            logger.info("Login fields not found; assuming login not required")

        # Initialize dictionary with router model name in Internet section
        router_info = {
            'Internet': {'Model': 'TP-LINK Archer C54'},
            'LAN': {},
            'DHCP Server': {},
            'Dynamic DNS': {},
            'Connected Devices': []
        }
        section_mapping = {
            'Internet': router_info['Internet'],
            'LAN': router_info['LAN'],
            'DHCP Server': router_info['DHCP Server'],
            'Dynamic DNS': router_info['Dynamic DNS']
        }
        skip_fields = {'Dynamic DNS': ['Status']}

        # Scrape networkStatus tab
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "div.panel-content-container"))
        )
        soup = BeautifulSoup(driver.page_source, 'html.parser')
        panels = soup.select("div[widget='panel']")
        for panel in panels:
            content_container = panel.find('div', class_='panel-content-container')
            if not content_container:
                continue

            title_label = content_container.find('div', class_='status-label-title')
            if not title_label:
                continue
            section_name = clean_text(title_label.find('label', class_='widget-fieldlabel').text)
            logger.info(f"Found section: {section_name}")

            # Extract key-value pairs
            labels = content_container.find_all('div', {'widget': 'displaylabel'}, class_=lambda x: x != 'status-label-title')
            section_data = {}
            has_valid_data = False
            for label in labels:
                field = label.find('label', class_='widget-fieldlabel')
                value = label.find('span', class_='text-wrap-display')
                if field and value:
                    key = clean_text(field.text)
                    val = clean_text(value.text)
                    if section_name in skip_fields and key in skip_fields[section_name]:
                        continue
                    section_data[key] = val
                    if val != 'Not Found':
                        has_valid_data = True

            if section_name in section_mapping and has_valid_data:
                section_mapping[section_name].update(section_data)

        # Scrape networkMap tab for Connected Devices
        logger.info(f"Navigating to {network_map_url}")
        driver.get(network_map_url)
        try:
            # Force navigation to networkMap tab
            driver.execute_script("window.location.hash = '#networkMap';")
            # Wait for table body with at least one row
            WebDriverWait(driver, 30).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "tbody.grid-content-data tr"))
            )
            # Add slight delay to ensure all rows load
            time.sleep(2)
            soup = BeautifulSoup(driver.page_source, 'html.parser')
            
            # Try to find the table body
            table_body = soup.select_one('tbody.grid-content-data')
            if not table_body:
                table_body = soup.select_one('table:has(tbody.grid-content-data) tbody')
                logger.info("Using fallback selector for table body")
            
            if table_body:
                logger.info("Found Connected Devices table body")
                rows = table_body.find_all('tr')
                logger.info(f"Found {len(rows)} rows in the table")
                for row in rows:
                    logger.debug(f"Processing row: {row.get('id', 'unknown')}")
                    cols = row.find_all('td')
                    logger.debug(f"Row has {len(cols)} columns")
                    if len(cols) >= 6:  # Need columns 1, 2, 5 (0-based indexing)
                        # Extract Device Name from column 1
                        device_name_elem = cols[1].select_one('div.td-content div.content')
                        device_name = clean_text(device_name_elem.text) if device_name_elem else 'Not Found'
                        
                        # Extract MAC Address and IP Address from column 2
                        mac_elem = cols[2].select_one('div.device-info-container div.mac')
                        ip_elem = cols[2].select_one('div.device-info-container div.ip')
                        mac_address = clean_text(mac_elem.text) if mac_elem else 'Not Found'
                        ip_address = clean_text(ip_elem.text) if ip_elem else 'Not Found'
                        
                        # Extract Connection Type from column 5
                        connection_elem = cols[5].select_one('div.connection-container')
                        connection_type = clean_text(connection_elem.text) if connection_elem else 'Not Found'
                        
                        # Only add device if at least one field is valid
                        if any(val != 'Not Found' for val in [device_name, mac_address, ip_address, connection_type]):
                            device = {
                                'Device Name': device_name,
                                'MAC Address': mac_address,
                                'IP Address': ip_address,
                                'Connection Type': connection_type
                            }
                            router_info['Connected Devices'].append(device)
                            logger.debug(f"Added device: {device}")
                        else:
                            logger.debug(f"Skipping row due to missing valid data: {row.get('id', 'unknown')}")
                    else:
                        logger.debug(f"Skipping row with {len(cols)} columns; expected at least 6")
            else:
                logger.warning("No table body with class 'grid-content-data' found")
                with open("network_map_page_source.html", "w", encoding="utf-8") as f:
                    f.write(soup.prettify())
                logger.info("Page source saved to 'network_map_page_source.html' for debugging")

        except TimeoutException:
            logger.warning("Timeout waiting for Connected Devices table rows")
            with open("network_map_page_source.html", "w", encoding="utf-8") as f:
                f.write(driver.page_source)
            logger.info("Page source saved to 'network_map_page_source.html' for debugging")

        # Print router information
        for section, data in router_info.items():
            if section != 'Connected Devices':
                print(f"\n**{section}**")
                for key, value in data.items():
                    print(f"{key}: {value}")

        # Print Connected Devices below router information
        print("\n**Connected Devices**")
        if router_info['Connected Devices']:
            print("| Device Name | MAC Address | IP Address | Connection Type |")
            print("|-------------|-------------|------------|-----------------|")
            for device in router_info['Connected Devices']:
                print(f"| {device['Device Name']} | {device['MAC Address']} | {device['IP Address']} | {device['Connection Type']} |")
        else:
            print("No connected devices found")

        return router_info

    except Exception as e:
        logger.error(f"Error scraping URLs: {str(e)}", exc_info=True)
        return None
    finally:
        driver.quit()

# Example usage
network_status_url = "https://emulator.tp-link.com/C54v1-US-Router/index.html#networkStatus"
network_map_url = "https://emulator.tp-link.com/c54-v1-eu-re/index.html#networkMap"
scrape_router_info(network_status_url, network_map_url)