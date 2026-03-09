from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime

packet_count = 0  # Global packet counter

def packet_callback(packet):
    global packet_count
    packet_count += 1

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Get timestamp
        time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print("\n==========================================")
        print(f"Packet Number: {packet_count}")
        print(f"Time Captured: {time_now}")
        print("------------------------------------------")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print("Protocol: TCP")
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print("Protocol: UDP")
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")

        else:
            print("Protocol: Other")

        print("==========================================")

print("Starting advanced packet capture...")
print("Press Ctrl+C to stop.\n")

# You can filter traffic here if needed
# Example: sniff(filter="tcp", ...)
sniff(prn=packet_callback, store=False)
