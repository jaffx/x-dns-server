#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "xdns.h"
#include <cstring>

#define DNS_IP "114.114.114.114"
#define DNS_PORT 53
#define DOMAIN_NAME "www.baidu.com"

int main() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in addr = {};
    addr.sin_addr.s_addr = inet_addr(DNS_IP);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DNS_PORT);

    char buffer[2048] = {};
    dns_datagram dd(DOMAIN_NAME);
    dd.header->set_qr_type(DNS_QR_REQUEST);
    dd.header->set_opcode(DNS_STD_QUERY);
    dd.header->set_Recursion_Available(true);
    dd.header->set_Recursion_Desired(true);
    auto &&buf_len = dd.to_seq(buffer, sizeof(buffer));

//    std::cout << buf_len << std::endl;
    auto t = sendto(sockfd, buffer, buf_len, 0, (sockaddr *) &addr, sizeof(addr));
    std::cout<<"成功发送字节数:"<<t<<std::endl;
    memset(buffer, 0, sizeof(buffer));
    sockaddr_in clnt_addr;
    socklen_t sz;
    recvfrom(sockfd, buffer, 2, 0, (sockaddr *) &addr, &sz);
    std::cout<<buffer<<std::endl;

}