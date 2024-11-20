import socket
import struct
import threading

# def discover(awsertTimeLimit):
#     print('oiii')
    
    
    
        
# def Main():
#     network = input("Insira IP:")
#     mask = input("Insira a máscara")
#     awnserTimelimit = input("Insira o tempo limite de respost:")

def main():
        target_ip = input("Enter target IP: ")
        port = int(input("Enter port (optional, press Enter to skip): ") or 0)
        data = input("Enter data (optional, press Enter to use default): ")
        ttl = int(input("Enter TTL (optional, press Enter to use default): ") or 64)
        icmp_id = int(input("Enter ICMP ID (optional, press Enter to use default): ") or 12345)

        icmp_packet_sender = IcmpPacketSender(target_ip, port, data, ttl, icmp_id)
        icmp_packet_sender.send_icmp_packet()
    
    
class IcmpPacketSender:
    def __init__(self, target_ip, port=None, data=None, ttl=64, icmp_id=12345):
        self.target_ip = target_ip
        self.port = port
        self.data = data
        self.ttl = ttl
        self.icmp_id = icmp_id
        
        
    def send_icmp_packet(self):
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
            s.settimeout(2)

            # Send the packet
            s.sendto(icmp_packet, (self.target_ip, 0))
            print("ICMP packet sent successfully!")

            # Wait for response
            response, addr = s.recvfrom(1024)
            print(f"Received response from {addr[0]}: {response}")

        except socket.timeout:
            print("No response received (timeout).")

        finally:
            s.close()

        
         
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
