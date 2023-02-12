//
// Created by lyn on 2023/2/11.
//

#ifndef TINY_DNS_SERVER_XDNS_H
#define TINY_DNS_SERVER_XDNS_H

#include <iostream>
#include <sys/socket.h>
#include <string>

#define DNS_QR_REQUEST 0
#define DNS_QR_RESPONSE 1

#define DNS_STD_QUERY 0
#define DNS_INVERSE_QUERY 1
#define DNS_SERVER_STATUS_QUERY 2

#define DNS_RCODE_OK 0
#define DNS_RCODE_FORMATTER_ERROR 1
#define DNS_RCODE_SERVER_ERROR 2
#define DNS_RCODE_DOMAIN_ERROR 3
#define DNS_RCODE_TYPE_ERROR 4
#define DNS_RCODE_REFUSED 5

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

    dns_header(const dns_header &);

    void set_flags(uint16_t) noexcept;

    int to_seq(char *, size_t) const;

    // flag设置和读取
    void set_qr_type(uint16_t type) noexcept;

    int get_qr_type() noexcept;

    void set_Authoritative(bool) noexcept;

    bool get_Authoritative() noexcept;

    void set_Truncated(bool) noexcept;

    bool get_Truncated() const noexcept;

    void set_Recursion_Desired(bool) noexcept;

    bool get_Recursion_Desired() const noexcept;

    void set_Recursion_Available(bool) noexcept;

    bool get_Recursion_Available() const noexcept;

    void set_opcode(uint16_t) noexcept;

    uint16_t get_opcode() const noexcept;

    void set_rcode(uint16_t) noexcept;

    uint16_t get_rcode() const noexcept;

};

class dns_query {
public:
    std::string q_name;
    uint16_t q_type;
    uint16_t q_class;

    dns_query();

    size_t size();

    dns_query(const dns_query &);

    dns_query(std::string, uint16_t type = 1);

    void create_dns_query_name(std::string name);

    void set_query_name(std::string);

    int to_seq(char *, size_t);

};

class dns_datagram {
public:
    dns_header *header;
    dns_query *query;

    dns_datagram();

    dns_datagram(std::string name);

    ~dns_datagram();

    dns_datagram operator=(const dns_datagram &);

    int to_seq(char *, size_t);


};

uint16_t get_dns_id() noexcept;

template<typename T>
int to_charlist(const T &, char *, size_t _size);

#endif //TINY_DNS_SERVER_XDNS_H
