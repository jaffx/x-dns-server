#include<cstdio>
#include<cstdlib>
#include<cstring>
#include<ctime>

#include<netinet/in.h>
#include<sys/socket.h>
#include<arpa/inet.h>

#include<iostream>

#define DNS_SERVER_PORT 53
#define DNS_SERVER_IP "114.114.114.114"

#define DNS_HOST			0x01
#define DNS_CNAME			0x05
//using namespace std;
//声明
static int dns_parse_response(char *buffer, struct dns_item **domains);

struct dns_header{
    unsigned short id;
    unsigned short flags;
    unsigned short questions;
    unsigned short answers;
    unsigned short authority;
    unsigned short additional;
};

struct dns_question{
    int length;
    unsigned short qtype;
    unsigned short qclass;
    char* name;//域名
};

struct dns_item {
    char *domain;
    char *ip;
};

//client send to dns server
int dns_create_header(dns_header* header){
    if(header==NULL) return -1;
    memset(header,0,sizeof(dns_header));

    //random
    srandom(time(NULL));//设置种子(因为种子根据时间有关，每次random也会变，因此这是一个线程不安全的)
    header->id=random();//获得随机数

    header->flags=htons(0x0100);//转化为网络字节序
    header->questions=htons(1);//每次查询一个域名
    return 0;

}

//创建question
//hostname:www.baidu.com
//name:3www5baidu3com'\0'
int dns_create_question(dns_question* question,const char* hostname){
    if(question==NULL||hostname==NULL) return -1;
    memset(question,0,sizeof(question));
    question->name=(char*)malloc(strlen(hostname)+2);//因为要判断结尾'\0'，然后再补充一个开头3
    if(question->name==NULL){//如果内存分配失败
        return -2;
    }
    question->length=strlen(hostname)+2;
    question->qtype=htons(1);//查询类型，（1表示：由域名获得 IPv4 地址）
    question->qclass=htons(1);//通常为 1，表明是 Internet 数据

    //hostname->name
    const char delim[2]=".";//分隔符,末尾补个'\0'
    char* qname=question->name;
    char* hostname_dup=strdup(hostname);//复制一份hostname  --->malloc(所以后续要free)
    char* token=strtok(hostname_dup,delim);
    while(token!=NULL){
        size_t len=strlen(token);//第一个循环token为www,len=3
        *qname=len;//先把长度放上去
        qname++;
        strncpy(qname,token,len+1);//复制www，这里不+1也是可以的，这样是为了把最后的'\0'也复制过来,因为最后也会被覆盖的。(如果这边不+1，最后一步，需要额外加上'\0')
        qname+=len;
        token=strtok(NULL,delim);//因为上一次，token获取还未结束，因此可以指定NULL即可。(注意：要依赖上一次的结果，因此也是线程不安全的)
    }
    free(hostname_dup);

}
#if 0
int dns_create_question(dns_question* question,const char* hostname){
    if(question==NULL||hostname==NULL) return -1;
    memset(question,0,sizeof(dns_question));
    question->name=(char*)malloc(strlen(hostname)+2);
    if(question->name==NULL) return -2;
    question->length=strlen(hostname)+2;
    question->qtype=htons(1);
    question->qclass=htons(1);

    // memset(question->name,0,question->length);
    int i=0,n=strlen(hostname);
    string hostname_tmp=(char*)hostname;
    string name;
    while(i<n){
        int start=i;
        while(i<n&&hostname_tmp[i]!='.') i++;
        name+=i-start;
        name+=hostname_tmp.substr(start,i-start);
        while(i<n&&hostname[i]=='.') i++;
    }
    for(int i=0;i<question->length;i++) question->name[i]=name[i];
    return 0;
}
#endif
//struct dns_header* header
//struct dns_question* question
//把上面两个合到request中 返回长度
int dns_build_requestion(dns_header* header,dns_question* question,char* request,int rlen){
    if(header==NULL||question==NULL||request==NULL) return -1;
    memset(request,0,rlen);

    //header-->request
    memcpy(request,header,sizeof(dns_header));//把header的数据 拷贝 到request中
    int offset=sizeof(dns_header);

    //question-->request
    memcpy(request+offset,question->name,question->length);
    offset+=question->length;
    memcpy(request+offset,&question->qtype,sizeof(question->qtype));
    offset+=sizeof(question->qtype);
    memcpy(request+offset,&question->qclass,sizeof(question->qclass));
    offset+=sizeof(question->qclass);
    return offset;
}

int dns_client_commit(const char* domin){
    int sockfd=socket(AF_INET,SOCK_DGRAM,0);//创建sockfd,AF_INET表示ipv4, SOCK_DGRAM为报文方式(UDP);
    if(sockfd<0){//创建失败
        std::cout<<"socket 创建失败"<<std::endl;
        return -1;
    }
    else{
        std::cout<<"socket 创建成功"<<std::endl;
    }
    sockaddr_in servaddr={0};//服务器地址(sockaddr_in存储)
    servaddr.sin_family=AF_INET;//协议簇(sockaddr_in_family)
    servaddr.sin_port=htons(DNS_SERVER_PORT);//端口
    servaddr.sin_addr.s_addr=inet_addr(DNS_SERVER_IP);//添加dns服务器ip
//    int bind_ret = bind(sockfd,(sockaddr*)&servaddr,sizeof(servaddr));
//    int ret=connect(sockfd,(sockaddr*)&servaddr,sizeof(servaddr));//在udp编程中可加可不加
//    printf("connect:%d",ret);

    dns_header header={0};
    dns_create_header(&header);
    dns_question question={0};
    dns_create_question(&question,domin);

    char request[1024]={0};//假设定义为1024长度
    int length = dns_build_requestion(&header,&question,request,1024);

    //request 发送请求
    int slen=sendto(sockfd,request,length,0,(sockaddr*)&servaddr,sizeof(sockaddr));

    //receive from 接受数据
    char response[1024]={0};
    sockaddr_in addr;
    size_t addr_len=sizeof(sockaddr_in);
    int n = recvfrom(sockfd,response,sizeof(response),0,(sockaddr*)&addr,(socklen_t*)&addr_len);
    // printf("recvfrom:%d \n",n);
    // for(int i=0;i<n;i++){
    //     printf("%c",response[i]);
    // }
    // for(int i=0;i<n;i++){
    //     printf("%x",response[i]);
    // }

    dns_item *dns_domain = NULL;
    dns_parse_response(response, &dns_domain);
    free(dns_domain);
    return n;
}

static int is_pointer(int in) {
    return ((in & 0xC0) == 0xC0);
}


static void dns_parse_name(unsigned char *chunk, unsigned char *ptr, char *out, int *len) {

    int flag = 0, n = 0, alen = 0;
    char *pos = out + (*len);

    while (1) {

        flag = (int)ptr[0];
        if (flag == 0) break;

        if (is_pointer(flag)) {

            n = (int)ptr[1];
            ptr = chunk + n;
            dns_parse_name(chunk, ptr, out, len);
            break;

        } else {

            ptr ++;
            memcpy(pos, ptr, flag);
            pos += flag;
            ptr += flag;

            *len += flag;
            if ((int)ptr[0] != 0) {
                memcpy(pos, ".", 1);
                pos += 1;
                (*len) += 1;
            }
        }

    }

}




static int dns_parse_response(char *buffer, struct dns_item **domains) {

    int i = 0;
    unsigned char *ptr = (unsigned char* )buffer;

    ptr += 4;
    int querys = ntohs(*(unsigned short*)ptr);

    ptr += 2;
    int answers = ntohs(*(unsigned short*)ptr);

    ptr += 6;
    for (i = 0;i < querys;i ++) {
        while (1) {
            int flag = (int)ptr[0];
            ptr += (flag + 1);

            if (flag == 0) break;
        }
        ptr += 4;
    }

    char cname[128], aname[128], ip[20], netip[4];
    int len, type, ttl, datalen;

    int cnt = 0;
    struct dns_item *list = (struct dns_item*)calloc(answers, sizeof(struct dns_item));
    if (list == NULL) {
        return -1;
    }

    for (i = 0;i < answers;i ++) {

        bzero(aname, sizeof(aname));
        len = 0;

        dns_parse_name((unsigned char* )buffer, ptr, aname, &len);
        ptr += 2;

        type = htons(*(unsigned short*)ptr);
        ptr += 4;

        ttl = htons(*(unsigned short*)ptr);
        ptr += 4;

        datalen = ntohs(*(unsigned short*)ptr);
        ptr += 2;

        if (type == DNS_CNAME) {

            bzero(cname, sizeof(cname));
            len = 0;
            dns_parse_name((unsigned char* )buffer, ptr, cname, &len);
            ptr += datalen;

        } else if (type == DNS_HOST) {

            bzero(ip, sizeof(ip));

            if (datalen == 4) {
                memcpy(netip, ptr, datalen);
                inet_ntop(AF_INET , netip , ip , sizeof(struct sockaddr));

                printf("%s has address %s\n" , aname, ip);
                printf("\tTime to live: %d minutes , %d seconds\n", ttl / 60, ttl % 60);

                list[cnt].domain = (char *)calloc(strlen(aname) + 1, 1);
                memcpy(list[cnt].domain, aname, strlen(aname));

                list[cnt].ip = (char *)calloc(strlen(ip) + 1, 1);
                memcpy(list[cnt].ip, ip, strlen(ip));

                cnt ++;
            }

            ptr += datalen;
        }
    }

    *domains = list;
    ptr += 2;

    return cnt;

}

int main(int argc,char* argv[]){
//    if(argc<2) return -1;
    dns_client_commit("www.baidu.com");
}