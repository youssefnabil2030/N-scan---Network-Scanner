from scapy.all import ARP, Ether, srp
import socket

def get_local_ip():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip

def scan_network(ip_range):
    # Create an ARP request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send the packet and receive the response
    result = srp(packet, timeout=2, verbose=0)[0]

    # Create a list of discovered devices
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def main():
    local_ip = get_local_ip()
    print(f"Local IP Address: {local_ip}")
    
    # Define the network range (e.g., '192.168.1.0/24')
    ip_range = f"{local_ip}/24"
    
    # Scan the network
    devices = scan_network(ip_range)
    
    # Display the discovered devices
    if devices:
        print("Available devices in the network:")
        print("IP" + " "*18+"MAC")
        for device in devices:
            print("{:16}    {}".format(device['ip'], device['mac']))
    else:
        print("No devices found.")

if __name__ == "__main__":
    main()
