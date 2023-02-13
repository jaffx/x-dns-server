//
// Created by lyn on 2023/2/11.
//

#include "xdns.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <utility>
#include <unordered_map>
#include <iomanip>
#include <cstdio>

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
    *(ptr + 3) = htons(this->answer_rrs);
    *(ptr + 4) = htons(this->authority_rrs);
    *(ptr + 5) = htons(this->additional_rrs);
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
    to_charlist<uint16_t>(qt_n, buffer + ptr, 2);
    ptr += 2;
    to_charlist<uint16_t>(qc_n, buffer + ptr, 2);
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
    this->set_name(std::move(name));
}

dns_query::dns_query(const dns_query &q) {
    *this = q;
}

void dns_query::name_to_qname() {
    this->q_name.resize(0);
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

void dns_query::qname_to_name() {
    this->name.resize(0);
    uint8_t seq_len;
    const char *buf = q_name.data();
    size_t ptr = 0, name_size = q_name.size();
    while (ptr < name_size) {
        strncpy((char *) &seq_len, (buf + ptr++), 1);
        for (uint8_t i = 0; i < seq_len; i++, ptr++)
            this->name += *(buf + ptr);
        if (ptr < name_size)
            this->name += '.';
        else
            break;
    }
}

void dns_query::set_name(std::string name) {
    this->name = std::move(name);
    this->name_to_qname();
}

dns_datagram dns_datagram::operator=(const dns_datagram &q) {
    this->header = new dns_header(*q.header);
    this->query = new dns_query(*q.query);
    this->rrs = q.rrs;
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

void dns_datagram::parse_header() {
    uint16_t *uint_ptr = (uint16_t *) (__ptr);
    this->header->id = ntohs(*uint_ptr);
    uint_ptr++;
    this->header->flags = ntohs(*uint_ptr);
    uint_ptr++;
    this->header->questions = ntohs(*uint_ptr);
    uint_ptr++;
    this->header->answer_rrs = ntohs(*uint_ptr);
    uint_ptr++;
    this->header->authority_rrs = ntohs(*uint_ptr);
    uint_ptr++;
    this->header->additional_rrs = ntohs(*uint_ptr);
    __ptr += 12;
}

void dns_datagram::parse_query() {
    // 判定是指针还是名字
    auto tp = (uint16_t *) __ptr;
    std::string &&name = ntohs(*tp) >= 0xc000 ? this->parse_name(ntohs(*tp) - 0xc000) : this->parse_name();
    auto uint_ptr = (uint16_t *) __ptr;
    this->query->q_type = ntohs(*uint_ptr);
    uint_ptr++, __ptr += 2;
    this->query->q_class = ntohs(*uint_ptr);
    uint_ptr++, __ptr += 2;
    this->query->name = std::move(name);
}


void dns_datagram::parse_rr() {
    dns_rr rr;
    auto tp = (uint16_t *) __ptr;
    // 解析域名
    std::string &&name = ntohs(*tp) >= 0xc000 ? this->parse_name(ntohs(*tp) - 0xc000) : this->parse_name();
    rr.name = name;
    // 解析Type 2 bytes
    auto uint_ptr = (uint16_t *) __ptr;
    rr.rr_type = ntohs(*uint_ptr);
    uint_ptr++, __ptr += 2;
    // 解析Class 2 bytes
    rr.rr_class = ntohs(*uint_ptr);
    uint_ptr++, __ptr += 2;
    // 解析TTL 4 bytes
    auto &&uint32_ptr = (uint32_t *) __ptr;
    rr.rr_ttl = ntohl(*uint32_ptr);
    __ptr += 4;
    // 解析数据长度 2 bytes
    uint_ptr = (uint16_t *) __ptr;
    rr.rr_data_len = ntohs(*uint_ptr);
    __ptr += 2;
    // 读取数据
    rr.data = parse_data(rr.rr_type, rr.rr_data_len);
    this->rrs.push_back(rr);
}

std::string dns_datagram::parse_data(uint16_t type, uint16_t len) {
    std::string ret;
    if (type == DNS_TYPE_A) {
        uint32_t ip = *(uint32_t *) (__ptr);
        __ptr += 4;
        char *p = inet_ntoa({ip});
        ret = p;
    } else if (type == DNS_TYPE_CNAME) {
        ret = parse_name(0, len);
    }
    return ret;
}

std::string dns_datagram::parse_name(uint16_t begin, uint16_t end) {
    /*
     * 如果begin=-1，从__ptr位置开始转化
     * 如果begin>=0，从__buffer+begin的位置开始转化
     *  转化到end结束，不再转化
     */
    if (begin > 0) {
        __ptr += 2;
        return this->names.at(begin);
    }

    std::string ret, seq;
    std::unordered_map<uint16_t, std::string> name_mps;
    auto seq_len = (uint8_t *) __ptr;
    const auto begin_ptr = __ptr;
    __ptr++;
    bool is_first = true;
    while ((end == 0 and *seq_len > 0) or (end > 0 and __ptr - begin_ptr < end)) {

        if (is_first) {
            is_first = false;
        } else {
            ret += ".";
            for (auto &kv: name_mps) {
                kv.second += '.';
            }
        }
        name_mps[__ptr - 1 - __buffer] = "";
        if (*seq_len >= 0xc0) {
            __ptr--;
            seq = parse_name(ntohs(*(uint16_t *) (__ptr)) - 0xc000);
            ret += seq;
        } else {
            seq = "";
            for (int i = 0; i < *seq_len; i++, __ptr++) {
                seq += *__ptr;
            }
            seq_len = (uint8_t *) __ptr;
            __ptr++;
            ret += seq;
        }

        for (auto &kv: name_mps) {
            kv.second += seq;
            this->names[kv.first] = kv.second;
        }
    }
    return ret;
}

void dns_datagram::set_buffer(char *buffer, size_t buffer_size) noexcept {
    this->__buffer = buffer;
    this->buf_size = buffer_size;
    this->__ptr = this->__buffer;
}

void dns_datagram::parse() {
    parse_header();
    for (int i = 0; i < this->header->questions; i++) {
        parse_query();
    }
    for (int i = 0; i < this->header->answer_rrs; i++) {
        parse_rr();
   }
}

void dns_datagram::show_info() {
    using std::cout, std::endl, std::setw;
    cout << std::left;
    int w = 12;
    int nums_w = 4;
    cout << "--------DNS HEADER INFO---------" << endl;
    cout << setw(w) << "ID " << this->header->id << endl;
    cout << setw(w) << "QR " << get_dns_qr_text(this->header->get_qr_type()) << endl;
    cout << setw(w) << "FLG " <<"0x"<<setw(4)<<std::setfill('0') << std::hex<< this->header->flags <<std::setfill(' ')<< std::dec << endl;
    cout << setw(w) << "RCODE " << get_dns_rcode_text(this->header->get_rcode()) << endl;
    cout << setw(w) << "OPCODE " << get_dns_opcode_text(this->header->get_opcode()) << endl;
    cout << setw(w) << "NUMS ";
    cout << "QU " << setw(nums_w) << this->header->questions;
    cout << "AN " << setw(nums_w) << this->header->answer_rrs;
    cout << "AU " << setw(nums_w) << this->header->authority_rrs;
    cout << "AD " << setw(nums_w) << this->header->additional_rrs << endl;
    cout << "---------------------------------" << endl;

    cout << "--------------QUERY" << "---------------" << endl;
    cout << setw(w) << "DOMAIN_NAME " << this->query->name << endl;
    cout << setw(w) << "TYPE " << get_dns_type_text(this->query->q_type) << endl;
    cout << setw(w) << "CLASS " << get_dns_class_text(this->query->q_class) << endl;
    cout << "----------------------------------" << endl << endl;

    for (int i = 0; i < this->header->answer_rrs; i++) {
        dns_rr &rr = this->rrs[i];
        cout << "--------Resource Record " << i + 1 << "---------" << endl;
        cout << setw(w) << "Name " << rr.name << endl;
        cout << setw(w) << "DATA LEN " << rr.rr_data_len << endl;
        cout << setw(w) << "DATA " << rr.data << endl;
        cout << setw(w) << "TYPE " << get_dns_type_text(rr.rr_type) << endl;
        cout << setw(w) << "TTL " << rr.rr_ttl << endl;
        cout << setw(w) << "CLASS " << get_dns_class_text(rr.rr_class) << endl;
        cout << "---------------------------------" << endl;
    }
    cout<<endl;
}

dns_datagram get_dns_response(int sockfd) {
    dns_datagram rep;
    char buffer[4096] = {};
    sockaddr_in addr;
    socklen_t sl;
    auto r_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (sockaddr *) &addr, &sl);
    rep.set_buffer(buffer, r_len);
    rep.parse();
//    rep.show_info();
    return rep;
}

std::string get_dns_rcode_text(uint16_t code) {
    std::string ret;
    switch (code) {
        case DNS_RCODE_OK:
            ret = "OK";
            break;
        case DNS_RCODE_SERVER_ERROR:
            ret = "SERVER_ERROR";
            break;
        case DNS_RCODE_DOMAIN_ERROR:
            ret = "DOMAIN_ERROR";
            break;

        case DNS_RCODE_FORMATTER_ERROR:
            ret = "FORMAT_ERROR";
            break;

        case DNS_RCODE_REFUSED:
            ret = "REFUSED";
            break;
        case DNS_RCODE_TYPE_ERROR:
            ret = "TYPE_ERROR";
            break;
        default:
            ret = "UNKNOWN";
            break;

    }
    return ret;
}

std::string get_dns_type_text(uint16_t type) {
    std::string ret;
    switch (type) {
        case DNS_TYPE_A:
            ret = "A";
            break;
        case DNS_TYPE_NS:
            ret = "NS";
            break;
        case DNS_TYPE_CNAME:
            ret = "CNAME";
            break;
        case DNS_TYPE_PTR:
            ret = "PTR";
            break;
        case DNS_TYPE_SOA:
            ret = "SOA";
            break;
        default:
            ret = "UNKNOWN";
            break;
    }
    return ret;
}

std::string get_dns_class_text(uint16_t cls) {
    std::string ret;
    switch (cls) {
        case DNS_CLASS_IN:
            ret = "IN";
            break;
        default:
            ret = "UNKNOWN";
            break;
    }
    return ret;
}

std::string get_dns_qr_text(uint16_t qr) {
    std::string ret;
    switch (qr) {
        case DNS_QR_REQUEST:
            ret = "DNS_REQUEST";
            break;
        case DNS_QR_RESPONSE:
            ret = "DNS_RESPONSE";
            break;
        default:
            ret = "UNKNOWN";
            break;
    }
    return ret;
}

std::string get_dns_opcode_text(uint16_t code) {
    std::string ret;
    switch (code) {
        case DNS_OPCODE_STD_QUERY:
            ret = "STAND_QUERY";
            break;
        case DNS_OPCODE_INVERSE_QUERY:
            ret = "INVERSE_QUERY";
            break;
        case DNS_OPCODE_SERVER_STATUS_QUERY:
            ret = "SERVER_STATUS_QUERY";
            break;
        default:
            ret = "UNKNOWN";
            break;
    }
    return ret;
}

dns_datagram do_dns(std::string domain_name, std::string dns_ip, uint16_t dns_port) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in addr = {};
    addr.sin_addr.s_addr = inet_addr(dns_ip.data());
    addr.sin_family = AF_INET;
    addr.sin_port = htons(dns_port);

    char buffer[2048] = {};
    dns_datagram dd(domain_name);
    dd.header->set_qr_type(DNS_QR_REQUEST);
    dd.header->set_opcode(DNS_OPCODE_STD_QUERY);
    dd.header->set_Recursion_Available(true);
    dd.header->set_Recursion_Desired(true);
    dd.show_info();
    auto &&buf_len = dd.to_seq(buffer, sizeof(buffer));

    auto t = sendto(sockfd, buffer, buf_len, 0, (sockaddr *) &addr, sizeof(addr));
    memset(buffer, 0, sizeof(buffer));

    return get_dns_response(sockfd);
}
