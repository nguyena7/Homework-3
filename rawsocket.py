import sys, socket, struct, select, time
TIMEOUT = 5
ICMP_ECHO = 8
MAX_DATA_SIZE = 64
ICMP_MAX_RECV = 4096

# rawsocket.py
class RawSocket:
    def __init__(self, remotehost):
        self.sock = None
        self.remotehost = remotehost
        self.ttl = 1
        self.port = 33435
        self.ip = self.getIP(remotehost)
        self.myID = 1234
        self.seqNumber = 0
        print("Tracing route to %s (%s)" % (self.remotehost, self.ip))
        # # # Info for current TTL # # #
        self.currentHost = ""
        self.currentIP = ""
        self.rtt = 0.0
        self.probe_count = 0

    def getIP(self, hostname):
        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            print("Failed to gethostbyname")
            return None
        return ip

    def createRawSocket(self):
        try:
            self.sock = socket.socket(
                family = socket.AF_INET,
                type = socket.SOCK_RAW,
                proto = socket.IPPROTO_ICMP
            )
        except socket.error as e:
            print("Failed to create raw socket. Socket Error: %s" % e.args[1])
            raise

    def checksum(self, packet):
        evenLength = (int(len(packet) / 2)) * 2
        sum = 0
        for count in range(0, evenLength, 2):
            sum = sum + (packet[count + 1] * 256 + packet[count])

        if evenLength < len(packet):
            sum += packet[-1]

        sum &= 0xffffffff
        sum = (sum >> 16) + (sum & 0xffff)
        sum += (sum >> 16)
        sum = ~sum & 0xffff
        return socket.htons(sum)

    def sendPing(self, ttl):
        """ Create an icmp packet first, then use raw socket to sendto this packet"""
        # # # Header has 8 bytes: type (8), code (8), checksum (16), id (16), sequence (16)
        checksum = 0
        header = struct.pack("!BBHHH", ICMP_ECHO, 0, checksum, self.myID, self.seqNumber)

        data = bytes(MAX_DATA_SIZE)
        packet = header + data

        checksum = self.checksum(packet)

        header = struct.pack("!BBHHH", ICMP_ECHO, 0, checksum, self.myID, self.seqNumber)
        packet = header + data

        self.ttl = ttl
        self.sock.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)

        try:
            num = self.sock.sendto(packet, (self.ip, self.port))
        except socket.error as e:
            print("Failed to send ping. Socket Error: %s" % e.args[1])
        return

    def recvPing(self): 
        self.probe_count += 1
        self.sock.setblocking(0)
        dataReady = select.select([self.sock], [], [], TIMEOUT)
        # # # Timeout, recursively call for retransmit
        if dataReady[0] == []:
            #self.recvPing()
            return False

        recPacket = b''
        recPacket, addr = self.sock.recvfrom(ICMP_MAX_RECV)
        self.currentIP = addr[0]

        ipHeader = recPacket[:20]

        iphVersion, iphTypeofSvc, iphLength, \
        iphID, iphFlags, iphTTL, iphProtocol, \
        iphChecksum, iphSrcIP, iphDestIP = struct.unpack("!BBHHHBBHII", ipHeader)

        # # # When the router IP address is the same as the DEST IP # # #
        if self.ip == addr[0]:
            return True

        icmpHeader = recPacket[20:28]

        icmpType, icmpCode, icmpChecksum, \
        icmpPacketID, icmpSeqNumber = struct.unpack("!BBHHH", icmpHeader)

        if icmpType == 3 and icmpCode == 3:
            print("Unreachable Host, Exiting")
            sys.exit()

    def close(self):
        self.sock.close()

    # # # main operation loop for this class # # #
    def trace(self):
        exe_time = 0
        for ttl in range(1, 30):
            self.createRawSocket()
            startTime = time.clock()
            self.sendPing(ttl)

            self.probe_count = 0
            ping_received = None
            while ping_received is not True:
                ping_received = self.recvPing()

                # # Reached Destination
                if ping_received is True: 
                    self.close()
                    totalTime = time.clock() - startTime
                    try:
                        # # # Get host name from current IP of router
                        temp = socket.gethostbyaddr(self.currentIP)
                        self.currentHost = temp[0]
                    except socket.herror:
                        self.currentHost = "< No DNS Entry >" 
                    print("%d %s (%s) %.3f ms (%d)" % (ttl, self.currentHost, self.currentIP, ((totalTime)*1000), self.probe_count))
                    break
                elif ping_received is None:
                    self.close()
                    totalTime = time.clock() - startTime
                    try:
                        temp = socket.gethostbyaddr(self.currentIP)
                        self.currentHost = temp[0]
                    except socket.herror:
                        self.currentHost = "< No DNS Entry >" 
                    print("%d %s (%s) %.3f ms (%d)" % (ttl, self.currentHost, self.currentIP, ((totalTime)*1000), self.probe_count))
                    break
                elif ping_received is False:
                    # # # Attempt retransmit if timeout occurs
                    self.close()
                    self.createRawSocket()
                    self.sendPing(ttl)
                    ping_received = self.recvPing()
                    
            exe_time += totalTime
            if ping_received is True:
                break
        print("\nTotal Execution Time: %.3f ms" % (exe_time * 1000))
        return

