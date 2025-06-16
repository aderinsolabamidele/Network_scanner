from argparse import ArgumentParser
from scapy.all import ARP, Ether, srp

parser = ArgumentParser(
    prog='Network Scanner',
    description='This is a network scanner that uses ARP requests.',
    epilog='Make sure to check out dvxillan!'
)

parser.add_argument('-t', "--target", help="Use -t to specify your target (in CIDR notation, e.g., 192.168.1.0/24)", required=True)

args = parser.parse_args()
target_ip = args.target

# Create ARP request and Ethernet frame
arp = ARP(pdst=target_ip)
ether = Ether(dst='ff:ff:ff:ff:ff:ff')
packet = ether / arp

# Send packet and capture response
result = srp(packet, timeout=3, verbose=0)[0]

clients = []

for sent, received in result:
    clients.append({'ip': received.psrc, 'mac': received.hwsrc})

# Display results
print("\nAvailable devices in the network:")
print("IP" + " " * 18 + "MAC")
print("-" * 40)
for client in clients:
    print("{:16}    {}".format(client['ip'], client['mac']))
