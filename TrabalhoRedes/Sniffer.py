#!/usr/bin/env python3
import socket
import struct
import time
from datetime import datetime
from ethernet_tools import EthernetFrame, IPV4, UDP, TCP, hexdump, packetTranslator, dnsTranslator, httpTranslator


domains = [
    "www",
    "mail",
    "remote",
    "blog",
    "webmail",
    "server",
    "ns1",
    "ns2",
    "smtp",
    "secure",
    "vpn",
    "m",
    "shop",
    "ftp",
    "mail2",
    "test",
    "portal",
    "ns",
    "ww1",
    "host",
    "support",
    "dev",
    "web",
    "bbs",
    "ww42",
    "mx",
    "email",
    "cloud",
    "1",
    "mail1",
    "2",
    "forum",
    "owa",
    "www2",
    "gw",
    "admin",
    "store",
    "mx1",
    "cdn",
    "api",
    "exchange",
    "app",
    "gov",
    "2tty",
    "vps",
    "govyty",
    "hgfgdf",
    "news",
    "1rer",
    "lkjkui",
    "pt",
    "ge"
]


history = []

ETH_P_ALL = 0x03 # Listen for everything
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))

def htmlGenerator():
    archiveName = 'history'
    content_html = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>History:</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #4CAF50; }}
            ul {{ list-style-type: square; }}
        </style>
    </head>
    <body>
        <h1>History</h1>
        <ul>
    """

    for site in history:
         content_html += f"""            <li>{site['dateTime']} - {site['ip']} - <a href="{site['site']}">{site['site']}</a></li>\n"""

    content_html += """
        </ul>
    </body>
    </html>
    """

    with open(f'{archiveName}.html', 'w', encoding='utf-8') as arquivo:
        arquivo.write(content_html)

    print(f"Archive {archiveName} created!")

try:
    while True:
        raw_data, addr = s.recvfrom(65565)
        # Ethernet

        frame = EthernetFrame(raw_data)
        # IPV4
        if frame.ETHER_TYPE == IPV4.ID:
            frame = EthernetFrame(raw_data)
            ipv4 = IPV4(frame.PAYLOAD)
            dest = ipv4.ipv4_to_str(ipv4.DESTINATION)
            src = ipv4.ipv4_to_str(ipv4.SOURCE)
            ipTarget = "192.168.0.96"
            if(src == ipTarget or dest == ipTarget ):
                print(str(frame))
                print(("└─ " + str(ipv4)))
                # UDP
                if ipv4.PROTOCOL == UDP.ID:
                    udp = UDP(ipv4.PAYLOAD)
                    if(udp.DEST_PORT == 53):
                        print(("   └─ " + str(udp)))
                        payload = hexdump(udp.PAYLOAD, 5)
                        print(payload)
                        packet = packetTranslator(udp.PAYLOAD)
                        print(packet)
                        addr = dnsTranslator(packet.strip())
                        if(addr != None):
                            temp = addr.split('.')
                            domain = temp[0]
                            print(domain)
                            if(domain in domains):
                                obj = {'dateTime': datetime.fromtimestamp(time.time()).strftime("%d/%m/%Y - %H:%M:%S"), 'site': 'https://' + addr + '/', 'ip': ipTarget }
                                if(obj not in history):
                                    repeated = False
                                    for i in history:
                                        if(i['site'] == f'http://{addr}/'):
                                            repeated = True

                                    if(not repeated):
                                        history.append(obj)
                # TCP
                if ipv4.PROTOCOL == TCP.ID:
                    tcp = TCP(ipv4.PAYLOAD)
                    if(tcp.DEST_PORT == 80 or tcp.SOURCE_PORT == 80):
                        print(("   └─ " + str(tcp)))
                        payload = hexdump(tcp.PAYLOAD, 5)
                        print(payload)
                        packet = packetTranslator(tcp.PAYLOAD)  
                        addr = httpTranslator(packet.strip())
                        if(addr != None  and 'www.' in addr):
                            obj = {'dateTime': datetime.fromtimestamp(time.time()).strftime("%d/%m/%Y - %H:%M:%S"), 'site': 'http://' + addr, 'ip': ipTarget } 
                            if(obj not in history):
                                index = 0
                                repeated = False
                                for i in history:
                                    if(i['site'] == f'https://{addr}'):
                                        repeated = True
                                        break

                                    index = index + 1

                                if(not repeated):
                                    history.append(obj)
                                else:
                                    del history[index]
                                    history.append(obj)

except KeyboardInterrupt:
    print("Program ended. Genereting results...")
    htmlGenerator()
