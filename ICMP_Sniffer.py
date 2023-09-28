from socket import *
import os
import struct


def parse_ip_header(ip_header):
    ip_headers=struct.unpack("!BBHHHBBH4s4s", ip_header[:20])
    ip_payloads=ip_header[20:]
    return ip_headers, ip_payloads


def parse_icmp_header(icmp_data):
    icmp_headers=struct.unpack("!BBHHH", icmp_data[:8])
    icmp_payloads=icmp_data[8:]
    return icmp_headers, icmp_payloads