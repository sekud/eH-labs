from scapy.all import sniff, ARP, Ether

# Dictionary to store IP-MAC mappings
ip_mac_map = {}

def process_packet(packet):
    if packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        src_mac = packet[Ether].src

        if src_mac in ip_mac_map:
            if ip_mac_map[src_mac] != src_ip:
                try:
                    old_ip = ip_mac_map[src_mac]
                except KeyError:
                    old_ip = "unknown"
                
                message = (f"\nPossible ARP attack detected!\n"
                           f"The machine with IP address {old_ip} is pretending to be {src_ip}\n")
                print(message)
        else:
            ip_mac_map[src_mac] = src_ip

# Sniff ARP packets
print("[*] Starting ARP spoofing detection...")
sniff(count=0, filter="arp", store=0, prn=process_packet)
