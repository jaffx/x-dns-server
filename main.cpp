#include <iostream>
#include <sys/socket.h>
#include "xdns.h"
#include <cstring>

int main() {
    dns_query dns_q("www.baidu.com");
    for(auto & c : dns_q.q_name)
        std::cout<<uint16_t(c)<<"\t"<<c<<std::endl;
}