import socket
import struct
import time
import threading

activeDevices = []
notActiveDevicesCount = 0
totalDiscoveryTime = 0 

def discover(network, waitingTime):
    ep = network.split('/')
    mask = int(ep[1])
    numHosts = (2 ** (32 - mask)) - 2
    ar = ep[0].split('.')
    start = int(ar[3]) + 1;
    end = start + numHosts;
    
    count = 1;
    for i in range(start, end):
        ip = f"{ar[0]}.{ar[1]}.{ar[2]}.{i}"
        print(f"Sending packet to {ip}") 
        icmp_packet_sender = IcmpPacketSender(ip, 0, 'oi', 128, count, waitingTime, notActiveDevicesCount, activeDevices)
        icmp_packet_sender.send_icmp_packet()
        count = count + 1
        

def printInfo(totalDiscoveryTime):
     # Imprime o cabeçalho
    print(f"{'IP':<15} {'Response Time (ms)'}")
    print("-" * 35)  # Linha de separação

    # Imprime os dados
    for device in activeDevices:
        print(f"{device['ip']:<15} {device['responseTime']:.4f}")
        
    print(f"Active Devices: {len(activeDevices)}")
    print(f"Total Devices: {len(activeDevices) + notActiveDevicesCount}")
    print(f"Total Discovery Time: {totalDiscoveryTime}")


def main():
        network = input("Enter network and mask:")
        waitingTime = input("Enter waiting time: ")
        # data = input("Enter data (optional, press Enter to use default): ") 
        
        discoveryStart = time.time()
        discover(network, waitingTime/1000)
        discoveryEnd = time.time()
        totalDiscoveryTime = discoveryEnd - discoveryStart
        printInfo(totalDiscoveryTime)
        
        # port = 0
        # icmp_id = 1234

        # icmp_packet_sender = IcmpPacketSender(target_ip, port, data, ttl, icmp_id)
        # icmp_packet_sender.send_icmp_packet()
    
    
class IcmpPacketSender:
    def __init__(self, target_ip, port, data, ttl, icmp_id, waitingTime, notActiveMachinesCount, activeDevices):
        self.target_ip = target_ip
        self.port = port
        self.data = data
        self.ttl = ttl
        self.icmp_id = icmp_id
        self.waitingTime = waitingTime
        self.notActiveMachinesCount = notActiveMachinesCount  # Atribuição direta
        self.activeDevices = activeDevices
        
    def send_icmp_packet(self):
        global notActiveDevicesCount  # Declarando como global para modificar o valor
        icmp_type = 8  # ICMP echo request
        icmp_code = 0
        icmp_checksum = 0
        icmp_sequence = 1

        # ICMP payload (data)
        icmp_payload = self.data.encode() if self.data else b"Hello, World!"

        # Initial ICMP header with checksum set to 0
        icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, self.icmp_id, icmp_sequence)

        # Calculate the checksum
        icmp_checksum = self.calculate_checksum(icmp_header + icmp_payload)

        # Repack the ICMP header with the correct checksum
        icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, self.icmp_id, icmp_sequence)

        # Create the full ICMP packet
        icmp_packet = icmp_header + icmp_payload

        # Send the ICMP packet
        try:
            # Create raw socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack("I", self.ttl))
            s.settimeout(int(self.waitingTime))

            # Send the packet
            s.sendto(icmp_packet, (self.target_ip, 0))
            print("ICMP packet sent successfully!")
            
            responseStart_time = time.time()

            # Wait for response
            response, addr = s.recvfrom(1024)
            print(f"Received response from {addr[0]}: {response}")
            
            responseEnd_time = time.time()
            
            device = {"ip": addr[0], "responseTime": responseEnd_time - responseStart_time}
            self.addDevice(device)

        except socket.timeout:
            print("No response received (timeout).")
            notActiveDevicesCount += 1 

        finally:
            s.close()
            
    def addDevice(self, device):
        isContained= False
        for i in range(len(activeDevices)):
            b = activeDevices[i]
            if(b["ip"] == device["ip"]):
                isContained = True
        
        if(not isContained):
            activeDevices.append(device)
        
    def calculate_checksum(self, data):
        checksum = 0

        # Handle odd-length data
        if len(data) % 2 != 0:
            data += b"\x00"

        # Sum each pair of bytes
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]  # Combine two bytes into a 16-bit word
            checksum += word

        # Fold 32-bit sum into 16 bits
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += (checksum >> 16)

        # Return one's complement of the checksum
        return ~checksum & 0xffff
    

    
main()
