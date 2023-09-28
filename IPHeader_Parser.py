from socket import *
import os
import struct


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

    packet_number=0
    try:
        while True:
            packet_number+=1
            data=sock.recvfrom(65535)
            ip_headers, ip_payloads=parse_ip_header(data[0]) # 함수에 패킷을 byte 형태로 넣어 주면 IP 헤더 20bytes의 headers와 나머지 데이터 payloads를 튜플 형태로 반환
            print(f"{packet_number} th packet\n")
            print("version: ", ip_headers[0]>>4) # ip_headers[0]은 1byte(8bytes)이며 bit 연산자(>>)를 이용해 왼쪽 4bits에 해당하는 값이 IP Version이 됩니다.
                                                # IP 헤더의 길이는 ip_headers[0]에서 오른쪽 4bits에 해당하는 값을 구하고 위드 단위인 4를 곱합니다.
            print("Header Length: ", ip_headers[0] & 0x0F) # 5를 출력. 단위가 워드(4bytes)이므로 20bytes가 됩니다.
            print("Type of Service: ", ip_headers[1])
            print("Total Length: ", ip_headers[2])
            print("Identification: ", ip_headers[3])
            print("IP Flags, Fragment Offset: ", flags_and_offset(ip_headers[3])) # bit 형태로 출력. '010'은 Do Not Fragment만 설정
            print("Time to Live: ", ip_headers[5])
            print("Protocol: ", ip_headers[6]) # ICMP(1), TCP(6), UDP(17) 출력
            print("Header Checksum: ", ip_headers[7])
            print("Source Address: ", inet_ntoa(ip_headers[8])) # ine_ntoa() 함수는 byte형을 우리가 읽을 수 있는 IP 주소 체계로 보여줍니다.
            print("Destination Address: ",inet_ntoa(ip_headers[9]))
            print("="*50)
    except KeyboardInterrupt: #Ctrl-C key input
        if os.name=="nt":
            sock.ioctl(SIO_RCVALL, RCVALL_OFF)
            sock.close()


def parse_ip_header(ip_header): # 패킷을 바이트 형태로 받아 헤더와 나머지 부분으로 반환합니다.
    ip_headers=struct.unpack("!BBHHHBBH4s4s", ip_header[:20]) # struct 모듈로 byte를 편하게 다룰 수 있다. (C, python)B: uchar 정수, H: hshort 정수, s: char bytes, L: ulong 정수, Q: ullong 정수   
                                        #Unpack의 첫 번째 인자에 해당하는 알파벳 형식에 따라 앞에서부터 byte를 끊어 튜플 형태로 반환. 두 번째 인자는 byte를 받음 !는 네트워크 byte 순서 의미
    ip_payloads=ip_header[20:]
    return ip_headers, ip_payloads


def flags_and_offset(int_num): # 숫자를 byte 형태로 변환시킨 후 bit 형태로 다시 출력합니다. .to_bytes(2, byteorder="big") 함수는 정수를 나타내는 byte 배열을 돌려줍니다. 2bytes길이 빅엔디안
    byte_num=int_num.to_bytes(2, byteorder="big")
    x=bytearray(byte_num)
    flags_and_flagment_offset=bin(x[0])[2:].zfill(8)+bin(x[1])[2:].zfill(8) # 1byte는 8bits이므로 zfill() 함수를 이용해 자릿수를 맞춰줌
    return(flags_and_flagment_offset[:3], flags_and_flagment_offset[3:])


if __name__=="__main__":
    host="localhost" # 자신의 IP 주소로 변겅
    print(f"Listening at [{host}]")
    parsing(host)