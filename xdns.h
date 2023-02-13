//
// Created by lyn on 2023/2/11.
//

#ifndef TINY_DNS_SERVER_XDNS_H
#define TINY_DNS_SERVER_XDNS_H

#include <iostream>
#include <sys/socket.h>
#include <string>
#include <vector>
#include <unordered_map>

#define DNS_QR_REQUEST 0
#define DNS_QR_RESPONSE 1

#define DNS_OPCODE_STD_QUERY 0
#define DNS_OPCODE_INVERSE_QUERY 1
#define DNS_OPCODE_SERVER_STATUS_QUERY 2

#define DNS_RCODE_OK 0
#define DNS_RCODE_FORMATTER_ERROR 1
#define DNS_RCODE_SERVER_ERROR 2
#define DNS_RCODE_DOMAIN_ERROR 3
#define DNS_RCODE_TYPE_ERROR 4
#define DNS_RCODE_REFUSED 5

#define DNS_TYPE_A 1
#define DNS_TYPE_NS 2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA 6
#define DNS_TYPE_PTR 12

#define DNS_CLASS_IN 1


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
    std::string name;

    dns_query();

    size_t size();

    dns_query(const dns_query &);

    dns_query(std::string, uint16_t type = 1);

    void name_to_qname();

    void qname_to_name();

    void set_name(std::string);

    int to_seq(char *, size_t);

};



class dns_rr {
public:
    std::string rr_name;
    std::string name;
    uint16_t rr_type;
    uint16_t rr_class;
    uint32_t rr_ttl;
    uint16_t rr_data_len;
    std::string data;
    uint8_t type;
};

class dns_datagram {
    char *__buffer, *__ptr;
    size_t buf_size;
public:
    dns_header *header;
    dns_query *query;
    std::vector<dns_rr> rrs;
    std::unordered_map<uint16_t, std::string> names;

    dns_datagram();

    dns_datagram(std::string name);

    ~dns_datagram();

    dns_datagram operator=(const dns_datagram &);

    int to_seq(char *, size_t);

    void set_buffer(char *buffer, size_t buffer_size) noexcept;

    void parse();

    std::string parse_name(uint16_t begin = 0, uint16_t end = 0);

    void parse_header();

    void parse_query();

    void parse_rr();

    std::string parse_data(uint16_t, uint16_t);

    void show_info();

};


dns_datagram get_dns_response(int sockfd);

uint16_t get_dns_id() noexcept;

template<typename T>
int to_charlist(const T &, char *, size_t _size);

std::string get_dns_rcode_text(uint16_t);

std::string get_dns_opcode_text(uint16_t);

std::string get_dns_type_text(uint16_t);

std::string get_dns_class_text(uint16_t);

std::string get_dns_qr_text(uint16_t);

dns_datagram do_dns(std::string domain_name, std::string dns_ip = "114.114.114.114", uint16_t dns_port = 53) ;

#endif //TINY_DNS_SERVER_XDNS_H
