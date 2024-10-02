from scapy.layers.inet import IP, ICMP, TCP
from scapy.all import rdpcap
from collections import defaultdict
from pyvis.network import Network


def detect_icmp_flood(pcap_file, threshold=5):
    # Read packets from the PCAP file
    packets = rdpcap(pcap_file)

    # Create a dictionary to track destination IPs and their corresponding source IPs for ICMP messages
    icmp_map = defaultdict(set)

    # Iterate through packets to find ICMP Destination Unreachable messages
    for pkt in packets:
        if ICMP in pkt and pkt[ICMP].type == 3:  # Type 3 is Destination Unreachable
            dest_ip = pkt[IP].dst
            src_ip = pkt[IP].src

            # Add the source IP to the set of sources for this destination IP
            icmp_map[dest_ip].add(src_ip)

    # Check for flood conditions based on unique source IPs targeting the same destination
    flood_ips = {dest_ip: len(sources) for dest_ip, sources in icmp_map.items() if len(sources) > threshold}

    if flood_ips:
        print("Potential ICMP Flood Detected:")
        for dest_ip, count in flood_ips.items():
            print(f"Destination IP: {dest_ip}, Unique Source Count: {count}")

        # Visualization
        visualize_flood(icmp_map)
    else:
        print("No ICMP Flood Detected")


def visualize_flood(icmp_map):
    net = Network(notebook=True, cdn_resources='in_line')  # Set cdn_resources to 'in_line'

    for dest_ip, sources in icmp_map.items():
        for src_ip in sources:
            net.add_node(src_ip, label=src_ip)
            net.add_node(dest_ip, label=dest_ip)
            net.add_edge(src_ip, dest_ip)

    net.show("icmp_flood_visualization.html")


# Example usage
detect_icmp_flood("PUT PATH OF PCAP FILE HERE", threshold=5)