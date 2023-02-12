//
// Created by lyn on 2023/2/11.
//

#include "xdns.h"

#include <utility>

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

dns_header::dns_header(const dns_header &h) {
    *this = h;
}

void dns_header::set_flags(uint16_t flag) noexcept {
    this->flags = flag;
}

void dns_header::set_qr_type(uint16_t type) noexcept {
    if (type == DNS_QR_REQUEST)
        // 查询第一位置为0
        this->flags &= 0x7FFF;
    else
        // 响应第一位置为1
        this->flags |= 0x8000;
}

int dns_header::get_qr_type() noexcept {
    if (this->flags & 80)
        // 1表示是响应
        return DNS_QR_RESPONSE;
    else
        return DNS_QR_REQUEST;
}

void dns_header::set_Authoritative(bool open) noexcept {
    if (open)
        this->flags |= 0x0400;
    else
        this->flags &= 0xFBFF;
}

bool dns_header::get_Authoritative() noexcept {
    return this->flags & 0x0400;
}

void dns_header::set_Truncated(bool open) noexcept {
    if (open)
        this->flags |= 0x0200;
    else
        this->flags &= 0xFDFF;
}

bool dns_header::get_Truncated() const noexcept {
    return this->flags & 0x0200;
}

void dns_header::set_Recursion_Desired(bool open) noexcept {
    if (open)
        this->flags |= 0x0100;
    else
        this->flags &= 0xFEFF;

}

bool dns_header::get_Recursion_Desired() const noexcept {
    return this->flags & 0x0100;
}

void dns_header::set_Recursion_Available(bool open) noexcept {
    if (open)
        this->flags |= 0x0080;
    else
        this->flags &= 0xFF7F;
}

bool dns_header::get_Recursion_Available() const noexcept {
    return this->flags & 0x0080;
}


void dns_header::set_opcode(uint16_t code) noexcept {
    code &= 0x000F;
    code <<= 11;
    this->flags &= 0x87FF;
    this->flags |= code;
}

uint16_t dns_header::get_opcode() const noexcept {
    uint16_t ret = this->flags;
    ret &= 0x7800;
    ret >>= 11;
    return ret;

}

void dns_header::set_rcode(uint16_t code) noexcept {
    code &= 0x000F;
    this->flags &= 0xFFF0;
    this->flags |= code;
}

uint16_t dns_header::get_rcode() const noexcept {
    uint16_t ret = flags;
    ret &= 0x000F;
    return ret;
}

int dns_header::to_seq(char *buffer, size_t _size) const {
    if (_size < 12) {
        return -1;
    }
    auto *ptr = (uint16_t *) buffer;
    // ？？ 这里有没有必要将所有的数据都转化为网络字节序
    *ptr = htons(this->id);
    *(ptr + 1) = htons(this->flags);
    *(ptr + 2) = htons(this->questions);
    *(ptr + 3) = this->answer_rrs;
    *(ptr + 4) = this->authority_rrs;
    *(ptr + 5) = this->additional_rrs;
    return 12;
}

int dns_query::to_seq(char *buffer, size_t _size) {
    if (_size < 1 + this->q_name.size()) {
        return -1;
    }
    int ptr = 0;
    strcpy(buffer, this->q_name.data());
    ptr += q_name.size();
    *(buffer + ptr) = '\0';
    ptr++;
    auto qt_n = htons(q_type), qc_n = htons(q_class);
    std::cout<<qt_n<<qc_n<<std::endl;
    to_charlist<uint16_t>(qt_n, buffer+ptr, 2);
    ptr += 2;
    to_charlist<uint16_t>(qc_n, buffer+ptr, 2);
    ptr += 2;

    return ptr;
}

dns_query::dns_query() {
    this->q_type = 1;
    this->q_class = 1;
}

dns_query::dns_query(std::string name, uint16_t type) {
    this->q_type = type;
    this->q_class = 1;
    this->create_dns_query_name(std::move(name));
}

dns_query::dns_query(const dns_query &q) {
    *this = q;
}

void dns_query::create_dns_query_name(std::string name) {
    char *_name = new char[name.size() + 1];
    strcpy(_name, name.data());
    char *saveptr;
    char *p = strtok_r(_name, ".", &saveptr);
    uint16_t _size;
    char buffer[3] = {};
    while (p) {
        _size = strlen(p);
        to_charlist<uint16_t>(_size, buffer, sizeof(buffer));
        this->q_name += buffer;
        this->q_name += p;
        p = strtok_r(nullptr, ".", &saveptr);
    }
    delete[] _name;
}

void dns_query::set_query_name(std::string name) {
    this->create_dns_query_name(std::move(name));
}

dns_datagram dns_datagram::operator=(const dns_datagram &q) {
    this->header = new dns_header(*q.header);
    this->query = new dns_query(*q.query);
    return *this;
}

size_t dns_query::size() {
    return this->q_name.size() + 1 + 2;
}

int dns_datagram::to_seq(char *buffer, size_t _size) {
    this->header->questions = 1;
    int total = 0;
    auto res = header->to_seq(buffer, _size);
    if (res < 0)
        return -1;
    total += res;
    res = query->to_seq(buffer + total, _size - total);
    if (res < 0)
        return -1;
    total += res;
    return total;
}

dns_datagram::dns_datagram() {
    header = new dns_header();
    query = new dns_query();
}

dns_datagram::dns_datagram(std::string name) {
    header = new dns_header();
    query = new dns_query(std::move(name));
}

dns_datagram::~dns_datagram() {
    delete header;
    delete query;
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

