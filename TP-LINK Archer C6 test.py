import requests
import json
import time

# Configuration
URL = "https://emulator.tp-link.com/c6-eu-v2/data/status.json"
OUTPUT_FILE = "router_status.json"

def fetch_router_info():
    """Fetch connected devices, router status, and product info from the JSON endpoint."""
    try:
        response = requests.get(URL, timeout=10)
        response.raise_for_status()  # Check for HTTP errors
        data = response.json().get("data", {})  # Access the nested data
        
        # Extract connected devices
        devices = data.get("access_devices_wired", [])
        
        # Extract router status, mapping JSON keys to screenshot labels
        # WAN Section
        wan_status = {
            "MAC Address": data.get("wan_macaddr", "N/A"),
            "IP Address": data.get("wan_ipv4_ipaddr", "N/A"),
            "Subnet Mask": data.get("wan_ipv4_netmask", "N/A"),
            "Default Gateway": data.get("wan_ipv4_gateway", "N/A"),
            "Primary DNS": data.get("wan_ipv4_pridns", "N/A"),
            "Secondary DNS": data.get("wan_ipv4_snddns", "N/A"),
            "Connection Type": "Dynamic IP" if data.get("wan_ipv4_conntype") == "dhcp" else data.get("wan_ipv4_conntype", "N/A")
        }
        
        # LAN Section
        lan_status = {
            "MAC Address": data.get("lan_macaddr", "N/A"),
            "IP Address": data.get("lan_ipv4_ipaddr", "N/A"),
            "Subnet Mask": data.get("lan_ipv4_netmask", "N/A"),
            "DHCP": "On" if data.get("lan_ipv4_dhcp_enable") == "On" else "Off"
        }
        
        # Wireless 2.4GHz Section
        wireless_2g_status = {
            "Network Name (SSID)": data.get("wireless_2g_ssid", "N/A"),
            "Wireless Radio": "On" if data.get("wireless_2g_enable") == "on" else "Off",
            "Mode": data.get("wireless_2g_hwmode", "N/A").replace("bgn", "802.11b/g/n mixed"),  # Map to screenshot format
            "Channel Width": data.get("wireless_2g_htmode", "N/A").capitalize(),  # e.g., "auto" -> "Auto"
            "Channel": f"{data.get('wireless_2g_channel', 'N/A')} (Current Channel {data.get('wireless_2g_current_channel', 'N/A')})" if data.get("wireless_2g_current_channel") else data.get("wireless_2g_channel", "N/A"),
            "MAC Address": data.get("wireless_2g_macaddr", "N/A"),
            "WDS Status": "Disabled" if data.get("wireless_2g_wds_status") == "disable" else "Enabled"
        }
        
        # Guest Network 2.4GHz Section
        guest_2g_status = {
            "Network Name (SSID)": data.get("guest_2g_ssid", "N/A"),
            "Hide SSID": "Off" if data.get("guest_2g_hidden") == "off" else "On",
            "Wireless Radio": "Off" if data.get("guest_2g_enable") == "off" else "On",
            "Allow guests to see each other": "Off" if data.get("guest_isolate") == "off" else "On"
        }
        
        # Product Info Section (using provided HTML values or JSON if available)
        product_status = {
            "Firmware Version": data.get("firmware_version", "1.0 Build 20190101 rel.12345"),  # From HTML or JSON
            "Hardware Version": data.get("hardware_version", "Archer C6 v2.0")  # From HTML or JSON
        }
        
        # Structure output
        output_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "devices": devices,
            "router_status": {
                "WAN": wan_status,
                "LAN": lan_status,
                "Wireless 2.4GHz": wireless_2g_status,
                "Guest Network 2.4GHz": guest_2g_status,
                "Product Info": product_status
            }
        }
        
        # Print connected devices first
        print("Connected Devices:")
        print(f"Total connected devices: {len(devices)}")
        for idx, device in enumerate(devices, 1):
            print(f"{idx}. Details:")
            print(f"   Wire Type: {device.get('wire_type', 'N/A')}")
            print(f"   MAC Address: {device.get('macaddr', 'N/A')}")
            print(f"   IP Address: {device.get('ipaddr', 'N/A')}")
            print(f"   Hostname: {device.get('hostname', 'N/A')}")
        
        # Then print router info
        print("\nRouter Information:")
        print("  WAN:")
        for key, value in wan_status.items():
            print(f"    {key}: {value}")
        
        print("  LAN:")
        for key, value in lan_status.items():
            print(f"    {key}: {value}")
        
        print("  Wireless 2.4GHz:")
        for key, value in wireless_2g_status.items():
            print(f"    {key}: {value}")
        
        print("  Guest Network 2.4GHz:")
        for key, value in guest_2g_status.items():
            print(f"    {key}: {value}")
        
        # Finally, print product info
        print("  Product Info:")
        for key, value in product_status.items():
            print(f"    {key}: {value}")
        
        # Save to JSON file
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(output_data, f, indent=4)
        print(f"\n***Output saved to {OUTPUT_FILE}***")
        
        return output_data
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        return None
    except (KeyError, ValueError, json.JSONDecodeError) as e:
        print(f"Error parsing JSON: {e}")
        return None

if __name__ == "__main__":
    fetch_router_info()