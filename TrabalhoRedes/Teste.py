import socket 
import struct

ETH_P_ALL = 0x03
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))

data = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
SOURCE, DEST, LEN, CHKSUM = struct.unpack("! H H H H", data[:8])