# Attribution: this assignment is based on ICMP Traceroute Lab from Computer Networking: a Top-Down Approach by Jim Kurose and Keith Ross. 
# It was modified for use in CSC249: Networks at Smith College by R. Jordan Crouser in Fall 2022

from socket import *
from ICMPpinger import checksum
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2

# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise
def build_packet():
    # In the sendOnePing() method of the ICMP Ping exercise, firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.

    #---------------#
    # Fill in start #
    #---------------#
    # Header is 8 bytes: 
    #    type (1), code (1), checksum (2), id (2), sequence (2)
    # code is 0, id helps match echos and replies. Sequence is unused, set to 1.
    ID = os.getpid() & 0xffff
    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # b - 1 byte integer, H - 2 byte unsigned integer, h - 2 byte signed integer
    header = struct.pack("BBHHH", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1) 
    # d - double, 8 bytes
    data = struct.pack("d", time.time())

    # Calculate the checksum on the data and the dummy header. 
    myChecksum = checksum(''.join(map(chr, header+data)))

    # Get the right checksum, and put in the header 
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network byte order 
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1) 
        # TODO: Make the header in a similar way to the ping exercise.
        # Append checksum to the header.
        # Solution can be implemented in 10 lines of Python code.
        
    #-------------#
    # Fill in end #
    #-------------#

    # Don’t send the packet yet , just return the final packet in this function.
    packet = header + data # Bytes concatenation
    return packet

def get_route(hostname):
    destAddr = gethostbyname(hostname)
    print(f"Traceroute to {hostname} [{destAddr}]:")
    
    timeLeft = TIMEOUT
    for ttl in range(1,MAX_HOPS):
        for tries in range(TRIES):
            

            #---------------#
            # Fill in start #
            #---------------#
            icmp = getprotobyname("icmp")
            mySocket = socket(AF_INET, SOCK_RAW, icmp)
                # TODO: Make a raw socket named mySocket
                # Solution can be implemented in 2 lines of Python code.

            #-------------#
            # Fill in end #
            #-------------#

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)

            try:
                d = build_packet()
                t = time.time()
                mySocket.sendto(d, (hostname, 0))
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)

                if whatReady[0] == []: # Timeout
                    print(" * * * Request timed out.")
                    continue

                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect

                if timeLeft <= 0:
                    print(" * * * Request timed out.")
                    continue

            except timeout:
                continue

            else:
                #---------------#
                # Fill in start #
                #---------------#
                # To separate the IP header from the ICMP packet, we need the IP header length:
                # The first byte contains the IP version and the header length, both occupying 4 bits. Slice indexing with [0:1] pulls out the first byte without
                # python converting it to a base 10 integer. hex() converts it to a hex string where the first hex character represents the first four 
                # bits and the second character represents the second 4 bits. [1] pulls out the second character. Then it's converted to an int, and 
                # multiplied by 4 because the IP header length field specifies length in 4 bit increments.
                ipHeaderLen = int(recvPacket[0:1].hex()[1], base=16)*4 
                icmpType = recvPacket[ipHeaderLen] # It's the first byte after the IP header.
                    #TODO: Fetch the icmp type from the IP packet
                    # Solution can be implemented in 2 lines of Python code.

                #-------------#
                # Fill in end #
                #-------------#
                # Using the time recorded at send time (t)
                # because the timestamp we put in the echo
                # request was lost when our packet was dropped 
                # before reaching the destination.
                if icmpType == 11: # Time Exceeded Message
                    delay = timeReceived - t 
                    printTracerouteEntry(ttl, delay, addr[0])
                    break
                elif icmpType == 3: # Destination Unreachable Message
                    delay = timeReceived - t
                    printTracerouteEntry(ttl, delay, addr[0])
                    break
                elif icmpType == 0: # Echo Reply Message
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    printTracerouteEntry(ttl, timeReceived - timeSent, addr[0])
                    return
                else:
                    print("error")

            finally:
                mySocket.close()

def printTracerouteEntry(ttl, delay, ipAddr):
    try:
        hostName = gethostbyaddr(ipAddr)[0]
    except herror:
        hostName = ''
    print(" %d rtt= %.0f ms %s %s" %(ttl, (delay)*1000, ipAddr, hostName))


# Runs program
if __name__ == "__main__":
    target = sys.argv[1]
    get_route(target)
