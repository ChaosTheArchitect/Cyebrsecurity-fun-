import scapy.all as scapy

# Sample malicious IPs for demonstration purposes
MALICIOUS_IPS = ['192.168.1.100']  # Replace with any known malicious IP for testing

def sniff_packet(packet):
    # Check if packet has IP layer and is TCP or UDP
    if packet.haslayer(scapy.IP) and (packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP)):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        src_port = packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else packet[scapy.UDP].sport
        dst_port = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else packet[scapy.UDP].dport

        # Print packet details
        print(f"Source IP: {src_ip}, Source Port: {src_port} --> Destination IP: {dst_ip}, Destination Port: {dst_port}")

        # Traffic pattern analysis (for demonstration, we'll just check for common ports)
        if dst_port == 80:
            print("[INFO] HTTP traffic detected")
        elif dst_port == 443:
            print("[INFO] HTTPS traffic detected")

        # Malicious traffic detection
        if dst_ip in MALICIOUS_IPS:
            print("[ALERT] Traffic to known malicious IP detected!")

# Start sniffing
scapy.sniff(filter="ip", prn=sniff_packet)
