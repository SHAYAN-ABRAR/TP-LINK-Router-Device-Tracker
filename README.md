# TP-Link Router Client & Status Monitor

## Introduction
Network visibility is essential for maintaining security, performance, and control. Many consumer-grade routers provide useful information about connected devices and traffic, but this data is often buried in web interfaces that are not optimized for quick access.  

This Python project automates the process of logging into TP-Link routers, extracting connected client information, and presenting key network statistics in a clear, human-readable format. By streamlining monitoring tasks, it saves time and reduces the risk of overlooking critical details.

---

## Why This Matters
- **Security Awareness**: Identify unauthorized devices connected to your network.  
- **Performance Monitoring**: Track bandwidth usage and troubleshoot slow connections.  
- **Operational Efficiency**: Avoid repetitive manual checks through automated data retrieval.  
- **Transparency**: Gain structured insights into your LAN, WAN, and wireless environments.  

In short, this tool bridges the gap between raw router data and actionable insights for everyday users, students, and IT professionals alike.

---

## Features
- **Automated Authentication**  
  Handles MD5-based login required by TP-Link web interfaces.  

- **Connected Device Discovery**  
  Retrieves DHCP and wireless clients, showing hostname, MAC address, IP address, and lease time.  

- **Router Status Overview**  
  Displays LAN and WAN parameters including IP addresses, gateways, subnet masks, DNS servers, and connection type.  

- **Wireless Network Insights**  
  Lists active SSIDs and associated details.  

- **System Information**  
  Extracts firmware and hardware versions for maintenance and compatibility checks.  

- **Traffic Statistics**  
  Reports bytes and packets sent/received, enabling bandwidth tracking and usage analysis.  

---
