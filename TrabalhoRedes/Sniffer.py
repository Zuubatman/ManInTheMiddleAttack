#!/usr/bin/env python3
import socket
import struct
import time
from ethernet_tools import EthernetFrame, IPV4, UDP, TCP, hexdump, packetTranslator, dnsTranslator, httpTranslator

history = []

ETH_P_ALL = 0x03 # Listen for everything
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))

def htmlGenerator():
    archiveName = 'history'
    """
    Cria um arquivo HTML com uma lista de frutas.

    Args:
        nome_arquivo (str): Nome do arquivo HTML a ser criado.
        frutas (list): Lista de frutas para incluir na página HTML.
    """
    conteudo_html = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Lista de Frutas</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #4CAF50; }}
            ul {{ list-style-type: square; }}
        </style>
    </head>
    <body>
        <h1>Lista de Frutas</h1>
        <ul>
    """

    for site in history:
        conteudo_html += f"            <li>{site}</li>\n"

    conteudo_html += """
        </ul>
    </body>
    </html>
    """

    with open(f'{archiveName}.html', 'w', encoding='utf-8') as arquivo:
        arquivo.write(conteudo_html)

    print(f"Arquivo '{archiveName}' criado com sucesso!")

try:
    while True:
        raw_data, addr = s.recvfrom(65565)
        # Ethernet
        frame = EthernetFrame(raw_data)
        # print(str(frame))
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
                            history.append({'dateTime': time.time(), 'site': addr, 'ip': ipTarget })
                # TCP
                if ipv4.PROTOCOL == TCP.ID:
                    tcp = TCP(ipv4.PAYLOAD)
                    if(tcp.DEST_PORT == 80 or tcp.SOURCE_PORT == 80):
                        print(("   └─ " + str(tcp)))
                        payload = hexdump(tcp.PAYLOAD, 5)
                        print(payload)
                        packet = packetTranslator(tcp.PAYLOAD)  
                        addr = httpTranslator(packet.strip())
                        if(addr != None):
                            history.append({'dateTime': time.time(), 'site': addr, 'ip': ipTarget })
except KeyboardInterrupt:
    print("O programa foi interrompido.")
    htmlGenerator()
