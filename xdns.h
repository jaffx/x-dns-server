//
// Created by lyn on 2023/2/11.
//

#ifndef TINY_DNS_SERVER_XDNS_H
#define TINY_DNS_SERVER_XDNS_H

#include <iostream>
#include <sys/socket.h>
#include <string>

#define DNS_QR_REQUEST 0x0000
#define DNS_QR_RESPONSE 0x8000
//#define DNS_OPCODE_

class dns_header {
private:

public:
    uint16_t id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answer_rrs;
    uint16_t authority_rrs;
    uint16_t additional_rrs;
    dns_header();
    void set_flags(uint16_t) noexcept;
    int to_string(char* , size_t);
    std::string to_string() noexcept;
};

class dns_query {
public:
    std::string q_name;
    uint16_t q_type;
    uint16_t q_class;
    dns_query(std::string, uint16_t type=0);
    void create_dns_query_name(std::string name);

};

class dns_datagram{
public:
    dns_header header;
    dns_query query;

};

uint16_t get_dns_id() noexcept;
template <typename T> int to_charlist(const T&,char* , size_t _size);

#endif //TINY_DNS_SERVER_XDNS_H
