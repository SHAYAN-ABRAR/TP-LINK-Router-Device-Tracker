from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import time

def scrape_router_info(url):
    try:
        # Set up Selenium with headless Chrome
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        
        # Wait for page to load
        time.sleep(3)
        
        # Log in
        try:
            username_field = driver.find_element(By.ID, "userName")
            password_field = driver.find_element(By.ID, "pcPassword")
            login_button = driver.find_element(By.ID, "loginBtn")
            username_field.send_keys("admin")
            password_field.send_keys("admin")
            login_button.click()
            print("Logged in successfully")
            time.sleep(5)
        except Exception as e:
            print(f"Login failed or not required: {e}")
        
        # Navigate to networkStatus tab
        driver.execute_script("window.location.hash = '#networkStatus';")
        time.sleep(5)  # Increased wait time to ensure content loads
        
        # Get page source and parse
        soup = BeautifulSoup(driver.page_source, 'html.parser')
        driver.quit()
        
        # Initialize dictionary
        router_info = {
            'Internet': {},
            'LAN': {},
            'DHCP Server': {},
            'Dynamic DNS': {},
            'Connected Devices': []
        }
        
        def clean_text(text):
            return text.strip().replace('\n', '').replace('\t', '') if text else 'Not Found'
        
        # Find all panels
        panels = soup.find_all('div', {'widget': 'panel'})
        
        for panel in panels:
            # Get the panel content container
            content_container = panel.find('div', class_='panel-content-container')
            if not content_container:
                continue
            
            # Find the section title
            title_label = content_container.find('div', class_='status-label-title')
            if not title_label:
                continue
            section_name = clean_text(title_label.find('label', class_='widget-fieldlabel').text)
            print(f"Found section: {section_name}")  # Debugging print
            
            # Extract key-value pairs from display labels
            labels = content_container.find_all('div', {'widget': 'displaylabel'}, class_=lambda x: x != 'status-label-title')
            section_data = {}
            has_valid_data = False
            for label in labels:
                field = label.find('label', class_='widget-fieldlabel')
                value = label.find('span', class_='text-wrap-display')
                if field and value:
                    key = clean_text(field.text)
                    val = clean_text(value.text)
                    # Skip Status field for Dynamic DNS
                    if section_name == 'Dynamic DNS' and key.lower() == 'status':
                        continue
                    section_data[key] = val
                    if val != 'Not Found':
                        has_valid_data = True
            
            # Assign to appropriate section only if valid data exists
            if has_valid_data:
                if section_name == 'Internet':
                    router_info['Internet'] = section_data
                elif section_name == 'LAN':
                    router_info['LAN'] = section_data
                elif section_name == 'DHCP Server':
                    router_info['DHCP Server'] = section_data
                elif section_name == 'Dynamic DNS':
                    router_info['Dynamic DNS'] = section_data
            elif section_name == 'Connected Devices':
                # Check for table in the panel
                table = content_container.find('table')
                if table:
                    print("Table found for Connected Devices")  # Debugging print
                    rows = table.find_all('tr')  # More robust row detection
                    for row in rows:
                        cols = row.find_all('td')
                        if len(cols) >= 4:
                            device = {
                                'Device Name': clean_text(cols[0].text),
                                'MAC Address': clean_text(cols[1].text),
                                'IP Address': clean_text(cols[2].text),
                                'Connection Type': clean_text(cols[3].text)
                            }
                            router_info['Connected Devices'].append(device)
                        else:
                            print(f"Row with insufficient columns: {len(cols)} columns found")
                else:
                    print("No table found for Connected Devices")
        
        # Print the extracted information with headings
        if router_info['Internet']:
            print("**Internet**")
            for key, value in router_info['Internet'].items():
                print(f"{key}: {value}")
        if router_info['LAN']:
            print("\n**LAN**")
            for key, value in router_info['LAN'].items():
                print(f"{key}: {value}")
        if router_info['DHCP Server']:
            print("\n**DHCP Server**")
            for key, value in router_info['DHCP Server'].items():
                print(f"{key}: {value}")
        if router_info['Dynamic DNS']:
            print("\n**Dynamic DNS**")
            for key, value in router_info['Dynamic DNS'].items():
                print(f"{key}: {value}")
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
        print(f"Error scraping the webpage: {e}")
        return None
    finally:
        if 'driver' in locals():
            driver.quit()

# URL to scrape
url = "https://emulator.tp-link.com/C54v1-US-Router/index.html#networkStatus"

# Execute the scraping function
scrape_router_info(url)