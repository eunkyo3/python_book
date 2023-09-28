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


def parsing(host):
    #raw socket 생성 및 bind
    if os.name=="nt":
        sock_protocol=IPPROTO_IP
    else:
        sock_protocol=IPPROTO_ICMP
    sock=socket(AF_INET, SOCK_RAW, sock_protocol)
    sock.bind((host, 0))

    #socket 옵션
    sock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)

    #promiscuous mode 켜기
    if os.name=="nt":
        sock.ioctl(SIO_RCVALL, RCVALL_ON)    