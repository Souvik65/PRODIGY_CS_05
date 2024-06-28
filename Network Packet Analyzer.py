from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Open a file for writing
output_file = "network packet analyser_output.txt"

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        payload = packet[IP].payload
        
        protocol_name = "Unknown"
        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        elif protocol == 1:
            protocol_name = "ICMP"
        
        packet_info = (
            f"Source IP: {ip_src}\n"
            f"Destination IP: {ip_dst}\n"
            f"Protocol: {protocol_name}\n"
            f"Payload: {payload}\n"
            + "-" * 50 + "\n"
        )
        
        # Print packet information to the console
        print(packet_info)
        
        # Write packet information to the file
        with open(output_file, "a") as f:
            f.write(packet_info)

def main():
    # Start sniffing packets
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
