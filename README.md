# ICMP-Flood-Detection-and-Visualization-DDoS-

## Overview

This Python script analyzes PCAP files to detect potential ICMP flood and TCP SYN flood attacks. It utilizes the `scapy` library for packet analysis and the `pyvis` library for visualizing the relationships between source IPs and target IPs.

## Features

- **ICMP Flood Detection**:
  - Identifies multiple unique source IPs sending ICMP Destination Unreachable messages to specific destination IPs.
  - Tracks unique source IPs targeting each destination IP.
  - Determines potential flood conditions based on a defined threshold of unique source IPs.
  - Visualizes the relationships between source IPs and their corresponding destination IPs.

- **TCP SYN Flood Detection**:
  - Detects TCP SYN packets targeting a specified destination IP (default: `10.10.10.10`).
  - Counts unique source IPs attempting to establish connections with the target IP.
  - Visualizes the connections in an interactive network graph.

## Requirements

- Python 3.x
- Scapy: Install via `pip install scapy`
- PyVis: Install via `pip install pyvis`

## Usage

1. Place your PCAP file in the same directory as the script or provide the full path.
2. Call the detection functions with the desired parameters:

## Visualization 
The generated HTML files (icmp_flood_visualization.html and syn_target_visualization.html) can be opened in any web browser to explore the network relationships visually. The visualizations display how different source IPs are targeting specific destination IPs, allowing for a better understanding of potential flood patterns.

## Example Output
- Potential ICMP Flood Detected:
  - Destination IP: 192.168.1.100, Unique Source Count: 12
- Potential SYN Flood Detected:
  - Destination IP: 10.10.10.10, Unique Source Count: 8

## Conclusion 
This project provides a straightforward approach to identifying potential flood attacks in network traffic captured in PCAP files, along with visualizations to aid in analysis. By leveraging packet analysis and interactive visualizations, users can gain insights into network behavior and take necessary actions to mitigate potential threats.

### ICMP Flood Detection

```python
detect_icmp_flood("path_to_your_file.pcap", threshold=5)
