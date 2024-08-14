# -*- coding: UTF-8 -*-
# most classes must be ran with admin and the python3 command prefix.
import argparse
import select
import socket
import os
import struct
import time
import threading
from urllib.request import urlopen, Request
from urllib.error import HTTPError
# NOTE: Do not import any other modules - the ones above should be sufficient

import argparse

def setupArgumentParser() -> argparse.Namespace:
    # Create the main argument parser with a description
    parser = argparse.ArgumentParser(
        description='A collection of Network Applications developed for SCC.203.')

    # Set default values for common arguments
    parser.set_defaults(func=None, hostname='lancaster.ac.uk')

    # Create subparsers for different network applications
    subparsers = parser.add_subparsers(help='sub-command help')

    # Subparser for the "ping" command
    parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
    parser_p.set_defaults(timeout=2, count=10)
    parser_p.add_argument('hostname', type=str, help='host to ping towards')
    parser_p.add_argument('--count', '-c', nargs='?', type=int,
                          help='number of times to ping the host before stopping')
    parser_p.add_argument('--timeout', '-t', nargs='?',
                          type=int,
                          help='maximum timeout before considering request lost')
    parser_p.set_defaults(func=ICMPPing)

    # Subparser for the "traceroute" command
    parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                     help='run traceroute')
    parser_t.set_defaults(timeout=2, protocol='icmp')
    parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
    parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                          help='maximum timeout before considering request lost')
    parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                          help='protocol to send request with (UDP/ICMP)')
    parser_t.set_defaults(func=Traceroute)

    # Subparser for the "web" command
    parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
    parser_w.set_defaults(port=8080)
    parser_w.add_argument('--port', '-p', type=int, nargs='?',
                          help='port number to start web server listening on')
    parser_w.set_defaults(func=WebServer)

    # Subparser for the "proxy" command
    parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
    parser_x.set_defaults(port=8000)
    parser_x.add_argument('--port', '-p', type=int, nargs='?',
                          help='port number to start web server listening on')
    parser_x.set_defaults(func=Proxy)

    # Parse the command-line arguments
    args = parser.parse_args()
    return args


class NetworkApplication:

    def checksum(self, dataToChecksum: bytes) -> int:
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

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, seq: int, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationHostname, destinationAddress, seq, ttl, time))
        else:
            print("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationAddress, seq, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))

    def printOneTraceRouteIteration(self, ttl: int, destinationAddress: str, measurements: list, destinationHostname=''):
        latencies = ''
        noResponse = True
        for rtt in measurements:
            if rtt is not None:
                latencies += str(round(rtt, 3))
                latencies += ' ms  '
                noResponse = False
            else:
                latencies += '* ' 

        if noResponse is False:
            print("%d %s (%s) %s" % (ttl, destinationHostname, destinationAddress, latencies))
        else:
            print("%d %s" % (ttl, latencies))


class ICMPPing(NetworkApplication):
    def __init__(self, args):
        super().__init__()
        self.destination_address = socket.gethostbyname(args.hostname)
        self.timeout = args.timeout
        self.count = args.count
        self.sequence_number =  0
        self.identifier = os.getpid() &  0xFFFF
        self.packet_size =  50  # Standard ICMP Echo Request size
        self.packets_sent =  0
        self.packets_received =  0
        self.minimum_delay = float('inf')
        self.maximum_delay =  0
        self.total_delay =  0

        self.ping()

    def ping(self):
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_socket.settimeout(self.timeout)

        try:
            for _ in range(self.count):
                self.send_one_ping(icmp_socket, self.destination_address, self.identifier)
                delay = self.receive_one_ping(icmp_socket, self.destination_address, self.identifier)
                if delay is not None:
                    self.packets_received +=  1
                    self.update_delays(delay)
                else:
                    print("Request timed out.")
        except socket.timeout:
            print("Request timed out.")
        except OSError as e:
            print(f"An OS error occurred: {e}.")
        finally:
            icmp_socket.close()

        self.print_additional_details()

    def send_one_ping(self, icmp_socket, destination_address, identifier):
        icmp_header = self.create_icmp_header(identifier, self.sequence_number)
        icmp_packet = icmp_header + b"abcdefghijklmnopqrstuvwabcdefghi"  # Dummy data
        icmp_socket.sendto(icmp_packet, (destination_address,  1))  # Destination port is not meaningful in ICMP
        self.packets_sent +=  1
        self.sequence_number +=  1

    def receive_one_ping(self, icmp_socket, destination_address, identifier):
        start_time = time.time()
        try:
            _, curr_info = icmp_socket.recvfrom(65536)
            end_time = time.time()
            delay = round((end_time - start_time) *  1000,  2)
            return delay
        except socket.timeout:
            return None

    def create_icmp_header(self, identifier, sequence_number):
        icmp_header = struct.pack("bbHHh",  8,  0,  0, identifier, sequence_number)
        checksum = self.checksum(icmp_header + b"abcdefghijklmnopqrstuvwabcdefghi")
        icmp_header = struct.pack("bbHHh",  8,  0, checksum, identifier, sequence_number)
        return icmp_header

    def update_delays(self, delay):
        self.total_delay += delay
        self.minimum_delay = min(self.minimum_delay, delay)
        self.maximum_delay = max(self.maximum_delay, delay)

    def print_additional_details(self):
        packet_loss = ((self.packets_sent - self.packets_received) / self.packets_sent) *  100
        average_delay = self.total_delay / self.packets_received if self.packets_received >  0 else  0
        self.printAdditionalDetails(packet_loss, self.minimum_delay, average_delay, self.maximum_delay)


import select

class Traceroute(NetworkApplication):
    def __init__(self, args):
        super().__init__()
        self.destination_hostname = args.hostname
        self.timeout = args.timeout
        self.protocol = args.protocol.lower()
        self.destination_address = socket.gethostbyname(self.destination_hostname)
        self.max_hops = 30
        self.packet_size = 60
        self.traceroute()

    def traceroute(self):
        """Perform traceroute to the destination."""
        print(f"Traceroute to {self.destination_address} ({self.destination_hostname}), {self.max_hops} hops max, protocol: {self.protocol.upper()}")
        for ttl in range(1, self.max_hops + 1):
            sock = self.create_socket(ttl)
            if self.protocol == 'icmp':
                reached = self.icmp_ping(self.destination_address, sock, ttl)
            elif self.protocol == 'udp':
                reached = self.udp_ping(self.destination_address, sock, ttl)
            else:
                raise ValueError("Unsupported protocol. Use either 'icmp' or 'udp'.")
            
            if reached:
                print("Reached destination")
                break
            sock.close()

    def create_socket(self, ttl):
        """Create a socket based on the specified protocol."""
        if self.protocol == 'icmp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        elif self.protocol == 'udp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        else:
            raise ValueError("Unsupported protocol.")
        
        sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        return sock

    def icmp_ping(self, dest_addr, sock, ttl):
        """Send ICMP packet and wait for response."""
        header = struct.pack('bbHHh', 8, 0, 0, ttl, 1)
        chksum = self.checksum(header)
        header = struct.pack('bbHHh', 8, 0, chksum, ttl, 1)
        sock.sendto(header, (dest_addr, 1))
        return self.wait_for_reply(sock, ttl)

    def udp_ping(self, dest_addr, sock, ttl): 
        """Send UDP packet and wait for response."""
        sock.sendto(b'', (dest_addr, 33434 + ttl))
        return self.wait_for_reply(sock, ttl)

    def wait_for_reply(self, sock, ttl):
        """Wait for a reply to the sent packet."""
        start = time.time()
        try:
            ready = select.select([sock], [], [], self.timeout)
            if ready[0]:
                received_packet, addr = sock.recvfrom(1024)
                elapsed_time = (time.time() - start) * 1000
                print(f"From {addr[0]}: icmp_seq={ttl} Time={elapsed_time}ms")
                return addr[0] == self.destination_address
            else:
                print(f"{ttl} * * Request timed out.")
        except OSError as e:
            print(f"Error receiving packet: {e}")
        return False

class WebServer(NetworkApplication):
    def handleRequest(self, tcpSocket):
        request = tcpSocket.recv(1024).decode()
        lines = request.split('\n')
        method, path, version = lines[0].split()

        if method != 'GET':
            self.sendResponse(tcpSocket,  405, 'Method Not Allowed')
            return

        if path == '/':
            path = '/index.html'

        filename = os.path.join(os.getcwd(), path[1:])
        if not os.path.isfile(filename):
            self.sendResponse(tcpSocket,  404, 'Not Found')
            return

        with open(filename, 'rb') as f:
            file_content = f.read()

        headers = [
            ('Content-Type', 'text/html'),
            ('Content-Length', str(len(file_content)))
        ]

        self.sendResponse(tcpSocket,  200, 'OK', headers, file_content)

    def sendResponse(self, tcpSocket, status_code, reason, headers=None, body=None):
        response = f'HTTP/1.1 {status_code} {reason}\r\n'
        if headers:
            for key, value in headers:
                response += f'{key}: {value}\r\n'
        response += '\r\n'
        if body:
            response += body.decode()
        tcpSocket.sendall(response.encode())

    def __init__(self, args):
        self.port = args.port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('localhost', self.port))
        self.server_socket.listen(1)
        print(f'Web Server starting on port: {self.port}...')

        while True:
            conn, addr = self.server_socket.accept()
            client_thread = threading.Thread(target=self.handleRequest, args=(conn,))
            client_thread.start()

        self.server_socket.close()

class Proxy(NetworkApplication):
    def __init__(self, args):
        super().__init__()
        self.port = args.port
        self.cache_directory = 'cache'  # Define cache directory name
        self._ensure_cache_directory_exists()  # Ensure the cache directory exists
        self.server_socket = self._initialize_server_socket()
        print(f'Web Proxy starting on port: {self.port}...')
        self._run_proxy()

    def _ensure_cache_directory_exists(self):
        # Check if the cache directory exists, and create it if it doesn't
        if not os.path.exists(self.cache_directory):
            os.makedirs(self.cache_directory)
            print(f'Cache directory {self.cache_directory} created.')
        else:
            print(f'Cache directory {self.cache_directory} already exists.')

    def _initialize_server_socket(self):
        server_host = '0.0.0.0'
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((server_host, self.port))
        server_socket.listen(1)
        return server_socket

    def _run_proxy(self):
        print(f'Proxy is listening on port {self.port} ...')
        while True:
            client_conn, client_addr = self.server_socket.accept()
            request = client_conn.recv(1024).decode()
            print(f'Request: {request}')
            filename = self._parse_request(request)

            if filename == '/favicon.ico':
                print('Ignoring request for favicon.ico')
                client_conn.close()
                continue

            content = self._fetch_content(filename)
            response = self._build_http_response(content)
            client_conn.sendall(response.encode())
            client_conn.close()

    def _parse_request(self, request):
        try:
            headers = request.split('\n')
            top_header = headers[0].split()
            filename = top_header[1]
            if filename == '/':
                filename = '/index.html'
            return filename
        except IndexError:
            return '/'

    def _build_http_response(self, content):
        if content:
            return 'HTTP/1.1 200 OK\n\n' + content
        else:
            return 'HTTP/1.1 404 NOT FOUND\n\nFile Not Found'

    def _fetch_content(self, filename):
        content = self._fetch_from_cache(filename)
        if content:
            print('Fetched successfully from cache.')
        else:
            print('Not in cache. Fetching from server.')
            content = self._fetch_from_server(filename)
        return content

    def _fetch_from_cache(self, filename):
        try:
            with open('cache' + filename, 'r') as cached_file:
                return cached_file.read()
        except IOError:
            return None

    def _fetch_from_server(self, filename):
        url = 'http://127.0.0.1:8000' + filename
        try:
            response = urlopen(Request(url))
            content = response.read().decode('utf-8')
            self._save_in_cache(filename, content)
            return content
        except HTTPError:
            return None

    def _save_in_cache(self, filename, content):
        print(f'Saving a copy of {filename} in the cache')
        with open('cache' + filename, 'w') as cached_file:
            cached_file.write(content)

# Do not delete or modify the code below
if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)



