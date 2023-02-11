//
// Created by lyn on 2023/2/11.
//

#include "xdns.h"

uint16_t get_dns_id() noexcept {
    static uint16_t id_c = 0;
    return ++id_c;
}

void init_dns_header(struct dns_header *header) noexcept {
    memset(header, 0, sizeof(dns_header));
    header->id = get_dns_id();
    header->flags = htons(0x0100);
    header->questions = htons(1);
}

dns_header::dns_header() {
    this->flags = 0x0100;
    this->id = get_dns_id();
    this->questions = this->answer_rrs = this->authority_rrs = this->additional_rrs = 0;
}

void dns_header::set_flags(uint16_t flag) noexcept {
    this->flags = flag;
}

int dns_header::to_string(char *buffer, size_t __size) {
    if (__size < 12) {
        return -1;
    }
    uint16_t *ptr = (uint16_t *) buffer;
    *ptr = htons(this->id);
    *(ptr + 1) = htons(this->flags);
    *(ptr + 2) = htons(this->questions);
    *(ptr + 3) = htons(this->answer_rrs);
    *(ptr + 4) = htons(this->authority_rrs);
    *(ptr + 5) = htons(this->additional_rrs);
    return 0;
}

std::string dns_header::to_string() noexcept {
    char __buffer[21] = {};
    this->to_string(__buffer, sizeof(__buffer));
    return __buffer;
}

dns_query::dns_query(std::string name, uint16_t type ) {
    this->q_type = type;
    this->q_class = 1;
    this->create_dns_query_name(name);

}

void dns_query::create_dns_query_name(std::string name) {
    char *_name = new char[name.size() + 1];
    strcpy(_name, name.data());
    char *saveptr;
    char *p = strtok_r(_name, ".", &saveptr);
    uint16_t _size;
    char buffer[3]={};
    while (p) {
        _size = strlen(p);
        to_charlist<uint16_t>(_size, buffer, sizeof(buffer));
        this->q_name += buffer;
        this->q_name += p;
        p = strtok_r(nullptr, ".", &saveptr);
    }
    delete[] _name;
}

template<typename T>
int to_charlist(const T &_data, char *buffer, size_t _size) {
    /*
    @brief
        将data转化为char类型的字节序列，放到buffer里，buffer的最大长度为_size
    @return
        0   转化成功
        -1  转化失败
     */
    size_t ms = sizeof(T);
    if (_size < ms)
        return -1;
    char *ptr_dest = (char *) &_data, *ptr_src = buffer;
    for (int i = 0; i < ms; i++, ptr_src++, ptr_dest++) {
        *ptr_src = *ptr_dest;
    }
    return 0;
}

