# Attribution: this assignment is based on ICMP Traceroute Lab from Computer Networking: a Top-Down Approach by Jim Kurose and Keith Ross. 
# It was modified for use in CSC249: Networks at Smith College by R. Jordan Crouser in Fall 2022
from socket import *
from ICMPpinger import checksum
import os
import sys
import struct
import time
import select

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
    # Make the header in a similar way to the ping exercise.
    # Insert checksum into the header.

    # Header is 8 bytes: 
    #    type (1), code (1), checksum (2), id (2), sequence (2)
    # code is 0, ID helps match echos and replies. Sequence is unused, set to 1.
    ID = os.getpid() & 0xffff # "& 0xffff" ensures that ID is no more than 2 bytes long
    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # B - 1 byte unsigned integer, H - 2 byte unsigned integer
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
    #-------------#
    # Fill in end #
    #-------------#

    # Don’t send the packet yet , just return the final packet in this function.
    packet = header + data # Bytes concatenation
    return packet

def get_route(hostname):
    destAddr = gethostbyname(hostname)
    if destAddr != hostname:
        print(f"Traceroute to {hostname} [{destAddr}]:")
    else:
        print(f"Traceroute to {destAddr}:")
    
    for ttl in range(1,MAX_HOPS):
        timeLeft = TIMEOUT
        for tries in range(TRIES):
            if timeLeft <= 0:
                print(" * * * Request timed out.")
                break
            #---------------#
            # Fill in start #
            #---------------#
            # Make a raw socket named mySocket that only sends or receives ICMP packets
            icmp = getprotobyname("icmp")
            mySocket = socket(AF_INET, SOCK_RAW, icmp)
            #-------------#
            # Fill in end #
            #-------------#
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                # ------------------- Start Time -------------------
                timeSent = time.time()
                mySocket.sendto(d, (hostname, 0))
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                if whatReady[0] == []: # Timeout
                    print(" * * * Request timed out.")
                    break
                # Now we know we have data to receive:
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                # ------------------- End Time -------------------
                delay = timeReceived - timeSent # Using the time we recorded at send time because the timestamp we put in the echo
                # request is lost when our packet is dropped before reaching the destination.
                
                howLongInSelect = (timeReceived - startedSelect)
                timeLeft = timeLeft - howLongInSelect
            except timeout:
                continue
            else:
                #---------------#
                # Fill in start #
                #---------------#
                # Fetch the icmp type from the IP packet

                # To separate the IP header from the ICMP packet, we need the IP header length:
                # The first byte contains the IP version and the header length, both occupying 4 bits. Slice indexing with [0:1] pulls out the first byte without
                # python converting it to a base 10 integer. hex() converts it to a hex string where the first hex character represents the first four 
                # bits and the second character represents the second 4 bits. [1] pulls out the second character. Then it's converted to an int, and 
                # multiplied by 4 because the IP header length field specifies length in 4 bit increments.
                ipHeaderLen = int(recvPacket[0:1].hex()[1], base=16)*4 
                icmpType = recvPacket[ipHeaderLen] # It's the first byte after the IP header.
                    
                #-------------#
                # Fill in end #
                #-------------#
                # Time Exceeded Message: 11
                # Destination Unreachable Message: 3
                # Echo Reply Message: 0
                if icmpType in (11, 3, 0): 
                    printTracerouteEntry(ttl, delay, addr[0])
                    if icmpType == 0: # We got our Echo Reply Message! That means we reached the destination.
                        return # Exit route tracing function
                    break # Otherwise, move on to the next TTL value
                else:
                    print("error")

            finally:
                mySocket.close()
    print("") # Adds a newline

def printTracerouteEntry(ttl, delay, ipAddr):
    print(f" {ttl} rtt= {round(delay*1000)} ms {ipAddr}", end=" ", flush=True)
    try:
        hostName = gethostbyaddr(ipAddr)[0]
    except herror:
        hostName = ""
    print(hostName)


# Runs program
if __name__ == "__main__":
    target = sys.argv[1]
    get_route(target)
