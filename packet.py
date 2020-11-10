"""

 PACKET  -  c0mplh4cks

 a Packet Constructor and Interpreter

 v1.2.1

"""





# === Importing Dependencies === #
from struct import pack, unpack
from random import randint
from time import time







# === Mac Vendor Lookup === #
def maclookup(mac):
    mac = mac.upper().replace(":", "")

    for line in open("vendors.txt", "r"):
        if mac[:6] == line[:6]:
            return line.split("\t")[1].replace("\n", "")

    return "Unknown vendor"





# === Encode === #
class encode:
    def ip(ip):
        return b"".join( [pack(">B", int(n)) for n in ip.split(".")] )

    def mac(mac):
        return b"".join( [pack(">B", int(n, 16)) for n in mac.split(":")] )





# === Decode === #
class decode:
    def ip(ip):
        return ".".join( [str(n) for n in ip] )

    def mac(mac):
        return ":".join( ["{:02x}".format(n) for n in mac] )







# === Checksum === #
def checksum(header):
    header = b"".join(header)
    if len(header)%2 != 0:
        header += b"\x00"
    values = unpack( f">{ len(headers)//2 }H", header )
    n = '{:04x}'.format(sum(values))

    while len(n) != 4:
        n = "{:04x}".format( int(n[:len(n)-4, 16]) + int(n[len(n)-4:], 16) )

    return (65535 - int(n, 16))







# === Ethernet === #
class ETHERNET:
    def __init__(self, packet=b""):
        self.packet = packet

        if len(self.packet) >= 14:
            self.read()


    def build(self, src=(), dst=(), protocol=2048, data=b""):
        self.src, self.dst, self.protocol, self.data = src, dst, protocol, data

        packet = [
            encode.mac(dst[2]),     # Destination MAC
            encode.mac(src[2]),     # Source MAC
            pack(">H", protocol),   # Protocol/Type
            data                    # Data
        ]

        self.packet = b"".join(packet)

        return self.packet


    def read(self):
        packet = self.packet

        self.src = ( "", 0, decode.mac(packet[6:12]) )
        self.dst = ( "", 0, decode.mac(packet[:6]) )
        self.protocol = unpack( ">H", packet[12:14] )[0]
        self.data = packet[14:]






# === ARP === #
class ARP:
    def __init__(self, packet=b""):
        self.packet = packet

        if len(self.packet) >= 28:
            self.read()


    def build(self, src=(), dst=(), op=1, ht=1, pt=2048, hs=6, ps=4):
        self.src, self.dst, self.op, self.ht, self.pt, self.hs, self.ps = src, dst, op, ht, pt, hs, ps

        packet = [
            pack(">H", 1),          # Hardware type
            pack(">H", 2048),       # Protocol type
            pack(">B", 6),          # Hardware size
            pack(">B", 4),          # Protocol size
            pack(">H", op),         # Operation code
            encode.mac(src[2]),     # Sender MAC
            encode.ip(src[0]),      # Sender IP
            encode.mac(dst[2]),     # Target MAC
            encode.ip(dst[0])       # Target IP
        ]

        self.packet = b"".join(packet)

        return self.packet


    def read(self):
        packet = self.packet

        self.src = ( decode.ip(packet[14:18]), 0, decode.mac(packet[8:14]) )
        self.dst = ( decode.ip(packet[24:28]), 0, decode.mac(packet[18:24]) )
        self.op = unpack( ">H", packet[6:8] )[0]
        self.ht = unpack( ">H", packet[:2] )[0]
        self.pt = unpack( ">H", packet[2:4] )[0]
        self.hs = packet[4]
        self.ps = packet[5]
