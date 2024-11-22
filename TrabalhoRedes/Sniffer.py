#!/usr/bin/env python3
import socket
import struct
from ethernet_tools import EthernetFrame, IPV4, UDP, TCP, hexdump

ETH_P_ALL = 0x03 # Listen for everything

network = input("Enter network:")
router = input("Enter router: ")

network_ip_bytes = socket.inet_aton(network)
router_ip_bytes = socket.inet_aton(router)

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))

while True:
    raw_data, addr = s.recvfrom(65565)

    # Ethernet
    frame = EthernetFrame(raw_data)
    print(str(frame))

    # IPV4
    if ipv4.SOURCE in (network_ip_bytes, router_ip_bytes) or ipv4.DESTINATION in (network_ip_bytes, router_ip_bytes):
        ipv4 = IPV4(frame.PAYLOAD)
        print(("└─ " + str(ipv4)))

        # UDP
        if ipv4.PROTOCOL == UDP.ID:
            udp = UDP(ipv4.PAYLOAD)
            if udp.SOURCE_PORT == 53 or udp.DEST_PORT == 53:
                print(("   └─ " + str(udp)))
                print(hexdump(udp.PAYLOAD, 5))

        # TCP
        elif ipv4.PROTOCOL == TCP.ID:
            if tcp.SOURCE_PORT == 80 or tcp.DEST_PORT == 80:
                tcp = TCP(ipv4.PAYLOAD)
                try:
                    http_payload = tcp.PAYLOAD.decode('utf-8', errors='replace')

                    lines = http_payload.split("\r\n")
                    if lines and lines[0].startswith(("GET", "POST", "HEAD", "OPTIONS")):
                        method, path, _ = lines[0].split(" ", 2)

                        host = None
                        for line in lines:
                            if line.lower().startswith("host:"):
                                host = line.split(":", 1)[1].strip()

                        if host:
                            url = f"http://{host}{path}"
                            print("Link accessed:", url)

                except Exception as e:
                    pass  