from socket import *
import os


def parsing(host):
    #raw socket 생성 및 bind
    if os.name=="nt": #윈도우
        sock_protocol=IPPROTO_IP #(0)
    else: #리눅스
        sock_protocol=IPPROTO_ICMP #(1)
    sock=socket(AF_INET, SOCK_RAW, sock_protocol) #IPv4,, Raw 소켓 사용, 프로토콜 지정(생략가능)
    sock.bind((host, 0)) #호스트의 IP 주소와 포트를 연결 
                         #인자값으로 호스트와 포트 번호를 튜플 형태로 저장(0이면 알아서 설정)
    #socket 옵션
    sock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1) #(대상, 옵션, 설정값)

    #promiscuous mode <- 윈도우에 필요, 목적지 주소가 내가 아니더라도 패킷을 수신
    if os.name=="nt":
        sock.ioctl(SIO_RCVALL, RCVALL_ON)

    data=sock.recvfrom(65535) #수신할 버퍼(공간) 크기(bytes)를 정의
    print(data[0])

    #promiscuous 끄기
    if os.name=="nt":
        sock.ioctl(SIO_RCVALL, RCVALL_OFF)

    #소켓 종료
    sock.close()


if __name__=="__main__":
    host="localhost" #자신의 IP 주소로 변경
    print(f"Listening at [{host}]")
    parsing(host)