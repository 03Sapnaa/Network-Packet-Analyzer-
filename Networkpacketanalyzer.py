from scapy.all import sniff, IP, TCP, UDP, ARP
from collections import Counter

# Function to analyze packets
def analyze_packet(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        print(f"IP Packet: {ip_src} -> {ip_dst} | Protocol: {protocol}")
        
        if packet.haslayer(TCP):
            print(f"TCP Packet: {ip_src}:{packet[TCP].sport} -> {ip_dst}:{packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"UDP Packet: {ip_src}:{packet[UDP].sport} -> {ip_dst}:{packet[UDP].dport}")
    
    elif packet.haslayer(ARP):
        print(f"ARP Packet: {packet[ARP].psrc} -> {packet[ARP].pdst}")
    
    print("\n")

# Function to capture packets
def capture_packets(interface="eth0", packet_count=0):
    print(f"Starting packet capture on {interface}...")
    sniff(iface=interface, prn=analyze_packet, count=packet_count)

# Main Function
if __name__ == "__main__":
    interface = input("Enter the network interface to capture packets (e.g., eth0): ")
    packet_count = int(input("Enter the number of packets to capture (0 for unlimited): "))
    capture_packets(interface=interface, packet_count=packet_count)
