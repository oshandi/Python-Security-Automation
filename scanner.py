from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    print(f"[*] Scanning network: {ip_range}")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]

    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    return clients

if __name__ == "__main__":
    target_network = "192.168.8.1/24"
    devices = scan_network(target_network)

    print("\nFound Devices:")
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")