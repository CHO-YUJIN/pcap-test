#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h> //ip
#include <netinet/tcp.h> //tcp
#include <netinet/udp.h> //udp
#include <pcap.h> //pcap


void usage() {
   printf("syntax: pcap-test <interface>\n");
   printf("sample: pcap-test wlan0\n");
}

struct ether_addr
{
        unsigned char ether_addr_octet[6];
};

struct ether_header
{
        struct  ether_addr ether_dhost;
        struct  ether_addr ether_shost;
        unsigned short ether_type;
};


struct ip_header
{
        unsigned char ip_header_len:4;
        unsigned char ip_version:4;
        unsigned char ip_tos;
        unsigned short ip_total_length;
        unsigned short ip_id;
        unsigned char ip_frag_offset:5;
        unsigned char ip_more_fragment:1;
        unsigned char ip_dont_fragment:1;
        unsigned char ip_reserved_zero:1;
        unsigned char ip_frag_offset1;
        unsigned char ip_ttl;
        unsigned char ip_protocol;
        unsigned short ip_checksum;
        struct in_addr ip_srcaddr;
        struct in_addr ip_destaddr;
};

struct tcp_header
{
        unsigned short source_port;
        unsigned short dest_port;
        unsigned int sequence;
        unsigned int acknowledge;
        unsigned char ns:1;
        unsigned char reserved_part1:3;
        unsigned char data_offset:4;
        unsigned char fin:1;
        unsigned char syn:1;
        unsigned char rst:1;
        unsigned char psh:1;
        unsigned char ack:1;
        unsigned char urg:1;
        unsigned char ecn:1;
        unsigned char cwr:1;
        unsigned short window;
        unsigned short checksum;
        unsigned short urgent_pointer;
};


typedef struct {
   char* dev_;
} Param;

Param param  = {
   .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
   if (argc != 2) {
      usage();
      return false;
   }
   param->dev_ = argv[1];
   return true;
}

void print_ether_header(const unsigned char *data)
{
        struct  ether_header *eh;
        unsigned short ether_type;
        eh = (struct ether_header *)data;
        ether_type=ntohs(eh->ether_type);
        if (ether_type!=0x0800)
        {
                printf("ether type wrong\n");
                return ;
        }


        printf("\n============ETHERNET HEADER==========\n");
        printf("Destination MAC Address [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for dest
                    eh->ether_dhost.ether_addr_octet[0],
                    eh->ether_dhost.ether_addr_octet[1],
                    eh->ether_dhost.ether_addr_octet[2],
                    eh->ether_dhost.ether_addr_octet[3],
                    eh->ether_dhost.ether_addr_octet[4],
                    eh->ether_dhost.ether_addr_octet[5]);
        printf("Source MAC Address [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for src
                    eh->ether_shost.ether_addr_octet[0],
                    eh->ether_shost.ether_addr_octet[1],
                    eh->ether_shost.ether_addr_octet[2],
                    eh->ether_shost.ether_addr_octet[3],
                    eh->ether_shost.ether_addr_octet[4],
                    eh->ether_shost.ether_addr_octet[5]);


}

int print_ip_header(const unsigned char *data)
{
        struct  ip_header *ih;
        ih = (struct ip_header *)data;

        printf("\n============IP HEADER============\n");
        //printf("IPv%d ver \n", ih->ip_version);

        if(ih->ip_protocol != 6)
        {
            printf(">>>> %x\n", ih->ip_protocol);
            return 0;
            //printf("Protocol : TCP\n");
        }

        printf("Source IP Address : : %s\n", inet_ntoa(ih->ip_srcaddr) );
        printf("Destination IP Address : %s\n", inet_ntoa(ih->ip_destaddr) );

        // return to ip header size
        return ih->ip_header_len*4;
}

int print_tcp_header(const unsigned char *data)
{
        struct  tcp_header *th;
        th = (struct tcp_header *)data;

        printf("\n============TCP HEADER============\n");
        printf("Source Port Number : %d\n", ntohs(th->source_port) );
        printf("Destination Port Number : %d\n", ntohs(th->dest_port) );

        // return to tcp header size
        return th->data_offset*4;
}

void print_data(const unsigned char *data, struct pcap_pkthdr* header)
{
        struct ether_header *eth_hdr = (struct ether_header *)data;

        struct  ip *ip_hdr;
        ip_hdr = (struct ip*)data;

        struct  tcp_header *th;
        th = (struct tcp_header *)data;

        //struct ip *ip_hdr = (struct ip *)(data+sizeof(eth_hdr));
        u_int8_t ip_offset = ip_hdr->ip_hl;


        u_int32_t payload_len = header->caplen - sizeof(eth_hdr) - ip_offset*4 -sizeof(th);
        u_int32_t max = payload_len >= 8 ? 8 : payload_len;
        const u_char* pkt_payload = data; //+ sizeof(*eth_hdr)+sizeof(*ip_hdr);
        //printf("%d", sizeof(ip_hdr));
        printf("\n============Payload(Data)============\n");
        if(!payload_len){
                printf("No payload\n");
            }else{
                for(int i=0; i<max; i++) //printf("%02x ", *(pkt_payload+i));
                    printf("%02x ", pkt_payload[i]);
                printf("\n");
            }
}



int main(int argc, char* argv[]) {

    int offset=0;

   if (!parse(&param, argc, argv))
      return -1;

   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
   if (pcap == NULL) {
      fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
      return -1;
   }

   while (true) {
      struct pcap_pkthdr* header;
        const u_char* packet;
      int res = pcap_next_ex(pcap, &header, &packet);
      if (res == 0) continue;
      if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
         printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
         break;
      }
        //printf("%u bytes captured\n", header->caplen);

        print_ether_header(packet);
        packet = packet + 14;

        offset = print_ip_header(packet);
        if(offset == 0) continue;

        packet = packet + offset;
        offset = print_tcp_header(packet);
        packet = packet + offset;
        print_data(packet, header);
        printf("------------------------------------------------------");
   }

   pcap_close(pcap);
}
