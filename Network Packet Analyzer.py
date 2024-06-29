from scapy.all import *
from collections import defaultdict
import time
import threading
import os

# Configuration
TIME_WINDOW = 5  # Time window in seconds to count requests
HTTP_THRESHOLD = 100  # Number of HTTP requests considered unusual
ICMP_THRESHOLD = 100  # Number of ICMP requests considered unusual
SYN_THRESHOLD = 100  # Number of SYN packets considered unusual

# Initialize dictionaries to store the count of requests
http_request_count = defaultdict(int)
icmp_request_count = defaultdict(int)
syn_packet_count = defaultdict(int)
protocol_count = defaultdict(int)
bandwidth_usage = defaultdict(int)

def get_default_interface():
    return conf.iface  # Gets the default network interface

def packet_callback(packet):
    if packet.haslayer(IP):
        protocol_count[packet[IP].proto] += 1
        bandwidth_usage[packet[IP].src] += len(packet)
        
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:
            # ICMP echo request
            source_ip = packet[IP].src
            icmp_request_count[source_ip] += 1
        elif packet.haslayer(TCP):
            if packet[TCP].flags & 2:  # SYN flag
                source_ip = packet[IP].src
                syn_packet_count[source_ip] += 1
        elif packet.haslayer(TCP) and packet.haslayer(Raw):
            try:
                http_payload = packet[Raw].load.decode('utf-8')
                if 'Host: ' in http_payload:
                    source_ip = packet[IP].src
                    http_request_count[source_ip] += 1
            except UnicodeDecodeError:
                pass  # Ignore packets that can't be decoded as HTTP

def monitor_requests():
    try:
        # Capture packets in real-time
        sniff(iface=MONITOR_INTERFACE, prn=packet_callback, store=False, filter="ip")
    except Exception as e:
        print(f"An error occurred in monitor_requests: {e}")

def detect_spike():
    while True:
        time.sleep(TIME_WINDOW)
        
        total_http_requests = sum(http_request_count.values())
        total_icmp_requests = sum(icmp_request_count.values())
        total_syn_packets = sum(syn_packet_count.values())
        total_bandwidth_usage = sum(bandwidth_usage.values())
        
        print(f"\nTime window: {TIME_WINDOW} seconds")
        print(f"Total HTTP Requests: {total_http_requests}")
        print(f"Total ICMP Echo Requests: {total_icmp_requests}")
        print(f"Total SYN Packets: {total_syn_packets}")
        print(f"Total Bandwidth Usage: {total_bandwidth_usage} bytes")
        
        if total_http_requests > HTTP_THRESHOLD or total_icmp_requests > ICMP_THRESHOLD or total_syn_packets > SYN_THRESHOLD:
            print(''' 
                 ____    
            ''')
        
        # Reset the counts for the next time window
        http_request_count.clear()
        icmp_request_count.clear()
        syn_packet_count.clear()
        protocol_count.clear()
        bandwidth_usage.clear()

if __name__ == "__main__":
    try:
        # Get the default network interface
        MONITOR_INTERFACE = get_default_interface()

        # Run monitoring and detection in parallel
        monitor_thread = threading.Thread(target=monitor_requests)
        detect_thread = threading.Thread(target=detect_spike)

        monitor_thread.start()
        detect_thread.start()

        monitor_thread.join()
        detect_thread.join()
    except KeyboardInterrupt:
        print("Script interrupted by user. Exiting...")
    except Exception as e:
        print(f"An error occurred in the main block: {e}")
