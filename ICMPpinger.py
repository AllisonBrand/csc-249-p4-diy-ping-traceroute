# Attribution: this assignment is based on ICMP Pinger Lab from Computer Networking: a Top-Down Approach by Jim Kurose and Keith Ross. 
# It was modified for use in CSC249: Networks at Smith College by R. Jordan Crouser in Fall 2022, and by Brant Cheikes for Fall 2023.

from socket import * 
import os
import sys 
import struct 
import time 
import select 
import binascii

# IP protocol carried:
ICMP_PROTOCOL = 1
# ICMP message type
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

# -------------------------------------
# This method takes care of calculating
#   a checksum to make sure nothing was
#   corrupted in transit.
#  
# You do not need to modify this method
# -------------------------------------
def checksum(string): 
    csum = 0
    countTo = (len(string) // 2) * 2 
    count = 0

    while count < countTo: 
        thisVal = ord(string[count+1]) * 256 + ord(string[count]) 
        csum = csum + thisVal
        csum = csum & 0xffffffff 
        count = count + 2

    if countTo < len(string):
        csum = csum + ord(string[len(string) - 1]) 
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff) 
    csum = csum + (csum >> 16)

    answer = ~csum

    answer = answer & 0xffff
 
    answer = answer >> 8 | (answer << 8 & 0xff00) 
    return answer


def receiveOnePing(mySocket, ID, timeout, destAddr): 
    # timeout is for overall ping receive, so we have to
    # time how long we are in select calls. Socket may receive multiple 
    # packets, only one will be the ping of interest. 
    timeLeft = timeout
    
    while True:      
        startedSelect = time.time()
        # file descriptors to wait for  vv   vv    vv  availibility
        #                           read,  write, exception
        whatReady = select.select([mySocket], [], [], timeLeft)
        #    [] is passed because we aren't interested in files with write or exception events.
        howLongInSelect = (time.time() - startedSelect)
        timeLeft -= howLongInSelect
        if timeLeft <= 0: # Took too long in select.
            return "Request timed out."
        if whatReady[0] == []: # select timed out and we never received it.
            return "Request timed out."
        
        recPacket, addr = mySocket.recvfrom(1024)
        timeReceived = time.time()

    #---------------#
    # Fill in start #
    #---------------#
        # Fetch the ICMP header from the IP packet
        
        # The AF_INET address family is only compatiple with IPv4, so I'm not bothering to check that the received packet is IPv4 and not IPv6.

        # To separate the IP header from the ICMP packet, we need the IP header length:
        # The first byte contains the IP version and the header length, both occupying 4 bits. Slice indexing with [0:1] pulls out the first byte without
        # python converting it to a base 10 integer. hex() converts it to a hex string where the first hex character represents the first four 
        # bits and the second character represents the second 4 bits. [1] pulls out the second character. Then it's converted to an int, and 
        # multiplied by 4 because the IP header length field specifies length in 4 bit increments.
        ipHeaderLen = int(recPacket[0:1].hex()[1], base=16)*4 
        
        # Verification:
        if addr[0] != destAddr: # It should have come from the address we sent the ping to:
            continue
        protocol = recPacket[9] # The 10th byte in the IP header identifies the protocol of the data it carries.
        if protocol != ICMP_PROTOCOL: # If it's not ICMP, the packet received is not what we are looking for
            continue # This condition will never be true, becuase the raw socket we created on;ly accepts ICMP messages.
        icmpPacket = recPacket[ipHeaderLen:]
        if len(icmpPacket) != 16: # We expect to unpack a 16 byte echo reply:
            continue
        type, code, check_sum, id, seq, timeSent = struct.unpack('BBHHHd', icmpPacket)
        if type != ICMP_ECHO_REPLY or id != ID: # ID is used to match the echo reply to the echo request.
            continue

        # At this point, we have verified that it is an IMCP Echo Reply with the ID of the ping we sent out
        delay = timeReceived - timeSent
        ttl  = recPacket[8] # 9th byte in the IP header is the Time To Live
        return delay, ttl
    #---------------#
    # Fill in end #
    #---------------#
        
# C:\Users\allis\GitHub\csc-249-p4-diy-ping-traceroute> py ICMPpinger.py "www.cnbc.com"
# Pinging www.cnbc.com [23.35.66.135] 3 times using Python:
# got here
# b"E`\x00$\xe8y\x00\x008\x01D\xb7\x17#B\x87\x83\xe5w\xb9\x00\x00\x87\xca\xc4'\x01\x00\xf9\xd3\x96\x9aI]\xd9A"
# Ping 1 RTT Request timed out. sec
# got here
# b"E`\x00$\xeb]\x00\x008\x01A\xd3\x17#B\x87\x83\xe5w\xb9\x00\x00&\xa7\xc4'\x01\x00\xda\xf6\x16\x9bI]\xd9A"
# Ping 2 RTT Request timed out. sec
# got here
# b"E`\x00$\xf0\xad\x00\x008\x01<\x83\x17#B\x87\x83\xe5w\xb9\x00\x00G\xa8\xc4'\x01\x008\xf5\x97\x9bI]\xd9A"

# >>> struct.unpack('bbHbbbbbbbb', packet[8:20])

def sendOnePing(mySocket, destAddr, ID):
    '''Sends an ICMP echo request to destAddr. The echo data is a timestamp, 
    so the sender can determine how long it took for the pong to come back. '''
    # This method creates an ICMP Echo request header and stores the current 
    # timestamp as the payload. It then calculates a checksum for the ICMP packet,
    # replaces the header's dummy 0 checksum, and sends the packet. 

    # Header is 8 bytes: 
    #    type (1), code (1), checksum (2), id (2), sequence (2)
    # code is 0, id helps match echos and replies. Sequence is unused, set to 1.
    myChecksum = 0

    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    # b - 1 byte integer, H - 2 byte unsigned integer, h - 2 byte signed integer
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1) 
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
    packet = header + data # Bytes concatenation

    # AF_INET address includes IP address and port number
    #  port 1 is arbitrary/ignored, this is a connectionless protocol
    mySocket.sendto(packet, (destAddr, 1)) 

def doOnePing(destAddr, timeout): 
    icmp = getprotobyname("icmp")

    # SOCK_RAW is a powerful socket type. For more details:	http://sock-raw.org/papers/sock_raw
    mySocket = socket(AF_INET, SOCK_RAW, icmp) # Raw socket that only accepts or sends ICMP messages

    myID = os.getpid() & 0xFFFF # get the current process id, ensure it is no more than 16 bits
    sendOnePing(mySocket, destAddr, myID)
    results = receiveOnePing(mySocket, myID, timeout, destAddr)
 
    mySocket.close() 
    return results

def ping(host, timeout=1, repeat=3):

    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost 
    dest = gethostbyname(host)
    print(f"\nPinging {host} [{dest}] {repeat} times using Python with 8 bytes of data:")

    # Send ping requests to a server separated by approximately one second 
    # Do this only a fixed number of times as determined by 'repeat' argument
    numPings = 1
    rttList = []
    while (numPings <= repeat) :
        print(f"Ping {numPings}:", end=" ")
        pingResult = doOnePing(dest, timeout)
        if type(pingResult) == str: # It's a failure description
            print(pingResult)
        else: # Sucessful ping:
            delay, ttl = pingResult
            print(f"RTT {round(delay*1000, 2)} ms, TTL={ttl}")
            rttList.append(delay*1000)
        if numPings < repeat: # Don't do this after the last one.
            print("waiting one second...", end="", flush=True)
            time.sleep(1) # one second 
            print("\r                     \r", end="")
        numPings += 1
    print(f"Average RTT: {round(sum(rttList) / len(rttList), 3)} ms")

# Runs program
if __name__ == "__main__":
    # get target address from command line
    target = sys.argv[1]
    ping(target)
