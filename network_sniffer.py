from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime
import logging

logging.basicConfig(filename='packets.log', level=logging.INFO, format='%(message)s')

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        output = f"[{timestamp}] Packet: {ip_layer.src} -> {ip_layer.dst}"
        print(output)
        logging.info(output)

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            flags = tcp_layer.flags
            output = f"    TCP Port: {tcp_layer.sport} -> {tcp_layer.dport} (Flags: {flags})"
            print(output)
            logging.info(output)

        if packet.haslayer(UDP):
            udp_layer = packet[UDP]
            output = f"    UDP Port: {udp_layer.sport} -> {udp_layer.dport}"
            print(output)
            logging.info(output)

        packet_size = len(packet)
        output = f"    Packet Size: {packet_size} bytes"
        print(output)
        logging.info(output)

def start_sniffing(interface='wlan0', duration=60, packet_count=None):
    if packet_count:
        sniffer = AsyncSniffer(iface=interface, prn=packet_callback, promisc=True, count=packet_count)
    else:
        sniffer = AsyncSniffer(iface=interface, prn=packet_callback)

    sniffer.start()
    sniffer.join(timeout=duration)

    if sniffer.running:
        sniffer.stop()

start_sniffing(interface='wlan0', duration=60, packet_count=30)
