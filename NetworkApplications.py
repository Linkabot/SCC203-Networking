#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import base64
from ctypes import sizeof
from socket import *
import argparse
import socket
import os
import sys
import struct
import threading
import time
import select
from trace import Trace



ICMP_ECHO = 8
ICMP_ECHO_REPLY = 0
MAX_HOPS = 30
TIMEOUT = 1
MAX_REQUEST_LENGTH = 4096

cacheDict = {}


def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        #parser.set_defaults(func=Traceroute, hostname='bbc.co.uk',timeout = 4)
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=4)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=4, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))


class ICMPPing(NetworkApplication):
    startTime = 0

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        
        
        timeleft = timeout
        icmpSocket.settimeout(timeleft)
        
        try:
            recPacket, addr = icmpSocket.recvfrom(2048)
        except socket.timeout:
            print("timeout")
            return
            
        
        receiveTime = (time.time() * 1000)
        header = struct.unpack("bbHHh", recPacket[20:28])
        
    
        networkDelay = receiveTime - self.startTime

        return networkDelay

      
        # 1. Wait for the socket to receive a reply
        # 2. Once received, record time of receipt, otherwise, handle a timeout
        # 3. Compare the time of receipt to time of sending, producing the total network delay
        # 4. Unpack the packet header for useful information, including the ID
        # 5. Check that the ID matches between the request and reply
        # 6. Return total network delay
        

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        
        checksum = 0
         # 1. Build ICMP header
        ICMPheader = struct.pack(
            "bbHHh", ICMP_ECHO, 0, checksum, ID, 1)

        
        # 2. Checksum ICMP packet using given function  
        checksum = NetworkApplication.checksum(self, ICMPheader)
        # 3. Insert checksum into packet
        
        ICMPheader = struct.pack(
            "bbHHh", ICMP_ECHO, 0, checksum, ID, 1
        )
        # 4. Send packet using socket
        packet = ICMPheader
       
        icmpSocket.sendto(packet, (destinationAddress, 1))
       
        self.startTime = time.time() * 1000
        
		
        # 5. Record time of sending
        
    def doOnePing(self, destinationAddress, timeout):

        currentSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
         # 1. Create ICMP socket
        
        self.sendOnePing(currentSocket, destinationAddress, 0)
        # 2. Call sendOnePing function
        delay = self.receiveOnePing(currentSocket, destinationAddress, 0, timeout)
        # 3. Call receiveOnePing function

        currentSocket.close()
         # 4. Close ICMP socket

        return delay
        # 5. Return total network delay

       

    def __init__(self, args):
        timeout = 1
        print('Ping to: %s...' % (args.hostname))

        while 1 : 
            delay = self.doOnePing(args.hostname, timeout)
            print(delay)
            time.sleep(1)
            self.printOneResult(args.hostname, 50, delay, 60)
        
        # 1. Look up hostname, resolving it to an IP address
        # 2. Call doOnePing function, approximately every second
        # 3. Print out the returned delay (and other relevant details) using the printOneResult method
         # Example use of printOneResult - complete as appropriate
        # 4. Continue this process until stopped


class Traceroute(NetworkApplication):

    def ping(self, destination_address, icmp_socket, ttl, id, udp):
        
        checksum = 0 
        header = struct.pack("bbHHh", ICMP_ECHO, 0, checksum, id, 1)
        # 1. Build ICMP header
        checksum = NetworkApplication.checksum(self, header)
        # 2. Checksum ICMP packet using given function 
        header = struct.pack("bbHHh", ICMP_ECHO, 0, checksum, id, 1)
        # 3. Insert checksum into packet
        if args.protocol == "udp": 
            udp.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            udp.sendto(b"", (destination_address, 33434))
        else:
            icmp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        # making socket for ttl
            icmp_socket.sendto(header, (destination_address, 1))
        # 4. Send packet using socket
        startTime = time.time()
        # starting the delay 
        ready = select.select([icmp_socket], [], [], args.timeout)
        # if the socket is filled with data. This is my timeout condition

        if ready[0] == []:
            timeOut = 1
            return timeOut, 0, 0, 0, 0 
        # returns null to all my values 

        recv_packet, address = icmp_socket.recvfrom(1024)
 
        # receives data in the packet
        hostname = ''
        try: 
            host_details = socket.gethostbyaddr(address[0])
            if len(host_details) > 0:
                hostname = host_details[0]
        except:
            hostname = address[0]
        # attempts to get a hostname, if it doesnt, replaces it with the address. 
            
        packet = sys.getsizeof(recv_packet)
        # used to get the size of the packet
        timeOut = 0
        # there is no timeout, therefore the ping was successful
        delay = (time.time() - startTime) * 1000
        # calculate the delay
        

        return timeOut, packet, hostname, address[0], delay



    def __init__(self, args):
        
        destination_address = socket.gethostbyname(args.hostname)
      
        # getting the destination address from the command line
        print('Traceroute to: %s...' % (args.hostname))
        working = 0
        ttl = 1
        id = 1
        while(ttl < MAX_HOPS):
            try:
                icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.getprotobyname('udp'))

                icmp_socket.bind(("", 33434))
                udp_socket.bind(("", 33434))
                # make a udp and icmp socket with the correct ports and binds 
            except socket.error as exception:
                print ("error")
                os._exit(1)

            times = []
            averages = []
            for i in range(3):
                timeOut, packet, hostname, address, delay = self.ping(destination_address, icmp_socket, ttl, id, udp_socket)
                #timeOut, packet, hostname, address, delay = self.ping(destination_address, icmp_socket, ttl, id)

                if(timeOut == 1):
                    times.append("*")
                    #for the timeout 
                else:
                    host_name = hostname
                    address_name = address
                    ms = round(delay, 2 )
                    times.append(ms)
                    averages.append(ms)
                    working += 1
                    max_ms = max(averages)
                    min_ms = min(averages)
                    average_ms = round((sum(averages) / len(averages)), 2)
                    #showing a timeout situation
            
            if((times[0] == "*") and times[1] == "*" and times[2] == "*"):
                print(ttl, "* * *")
            else:
                print(ttl, "(bytes:", packet, ")",  host_name,"(",address_name,") ",times[0],"ms ",times[1],"ms ",times[2],"ms")
                print("|| minimum:", min_ms, "ms ||  average:", average_ms, "ms || maximum:", max_ms, "ms ||" )

            max_ms = 0
            min_ms = 0
            average_ms = 0
            host_name = ""
            address_name = ""
        

            if(address == destination_address):
                packets_not_connected = (ttl*3) - working
                packet_loss = ((packets_not_connected / (ttl * 3)) * 100) 
                #if address is met then itll close the loop
                print("packet loss:", round(packet_loss, 2), "%")
                print("finished")
                icmp_socket.close()
                break

            ttl += 1
            id +=1 
            
        os._exit(0)
class WebServer(NetworkApplication):

    def handleRequest(self, tcpSocket):
        
        received = tcpSocket.recv(1024)
        
        received = str(received)

        received = received.split(" ")
        
        filename = ''.join(received[1].split('/', 1))
            
        try:
            file = open(filename)
            f = file.read()
            file.close()
            #encode the the str
            
            
            
            # 3. Read the corresponding file from disk
            msg = f
        
            # 4. Store in temporary buffer
            response = "HTTP/1.1 200 OK\n\n"
            tcpSocket.sendall(bytearray(response.encode()))

            tcpSocket.sendall(bytearray(msg.encode()))
            # 6. Send the content of the file to the socket
        except FileNotFoundError:
                print("HTTP 404 ERROR")
            # response error
        # 5. Send the correct HTTP response error
        
        tcpSocket.close()
            # 7. Close the connection socket
        pass

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        self.tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 1. Create server socket
        self.tcpSocket.bind(("127.0.0.1", args.port))
        # 2. Bind the server socket to server address and server port
        self.tcpSocket.listen()
        # 3. Continuously listen for connections to server socket
        while True:
            (connection, address) = self.tcpSocket.accept()
            self.handleRequest(connection)
    
            break
        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
        self.tcpSocket.close()
        # 5. Close server socket


class Proxy(NetworkApplication):
    
    

    def handleRequest(self, tcpSocket):

        received = str(tcpSocket.recv(MAX_REQUEST_LENGTH).decode())
        # 1. Receive request message from the client on connection socket
        request = received.split()[0]
        first_line = received.split('\n')[0]
        print("first line: " , first_line)
        url = first_line.split(' ')[1]
        print("url: ", url)
        http_pos = url.find("://")
        print("http pos: ",http_pos)
        if (http_pos==-1):
            temp = url
        else:
            temp = url[(http_pos+3):]
        print("temp: ", temp)
        port_pos = temp.find(":")
        print("port_pos: " , port_pos)
        webserver_pos = temp.find("/")
        print("webserver_pos: ", webserver_pos)
        if webserver_pos == -1:
            webserver_pos = len(temp)
        # split the line up

        webserver = ""
        
        port = -1
        if (port_pos == -1 or webserver_pos < port_pos):

            port = 80
            webserver = temp[:webserver_pos]
        
        else: 
            port = int((temp[(port_pos+1):][:webserver_pos-port_pos-1]))
            webserver = temp[port_pos]
        print("webserver: ", webserver)
        #   get the webserver online

        if  request == "GET":
            try: 
                file = open(webserver, 'r')
                
                content = file.read()
                tcpSocket.sendall(content.encode())
                #check if its in the cache
            except Exception:

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((webserver, port))
                s.sendall(received.encode())
                #if its not in the cache, make a new socket
                
                message = b""
                while 1:
                    ready = select.select([s], [], [], 5)
                    #see's if data has been received before timeout

                    if (len(ready[0])> 0):
                        #if it hasnt timeout continue
                        data = s.recv(1024)
                        message = message + data
                        tcpSocket.send(data)
                        #send data, receiving it 1024 chuncks
                    else:
                        #timeout 
                        break
            
                tcpSocket.close()
                #close socket

                file = open(webserver, 'x')
                file.write(message.decode())
                file.close()
                #put new file into cache
            
        else:
            # If its not a get request (PUT or POST or DELETE)
            #basically do the same without the cache
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((webserver, port))
            s.sendall(received.encode())

            while 1:
                ready = select.select([s], [], [], 5)

                if (len(ready[0])> 0):
                    data = s.recv(1024)
                    tcpSocket.send(data)
                else:
                    break
                

        

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))
        self.tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcpSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # 1. Create server socket
        self.tcpSocket.bind(("", args.port))
        # 2. Bind the server socket to server address and server port
    
        # 3. Continuously listen for connections to server socket
        self.tcpSocket.listen()
        while True:
            (connection, address) = self.tcpSocket.accept()
            self.handleRequest(connection)
    


if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
