#ifndef PCAP_TEST_H
#define PCAP_TEST_H

#include <stdio.h>
#include <pcap.h>

#define SIZE_ETHERNET 14

struct sniff_ethernet{
    u_int8_t dhost[6];
    u_int8_t shost[6];
    u_int8_t type[2]; // next protocol number, ip(0x0800)  arp(0x0806)
};


struct sniff_ip{
    u_int8_t vhl;            // version
    u_int8_t tos;           // type of service
    u_int8_t len[2];       // total length
    u_int8_t id[2];
    u_int8_t off[2];
    u_int8_t ttl;
    u_int8_t p;            // protocol  tcp(6)  udp(17)
    u_int8_t sum[2];
    u_int8_t shost[4];
    u_int8_t dhost[4];
};


struct sniff_tcp{
    u_int8_t sport[2];
    u_int8_t dport[2];
    u_int th_seq;          // sequence number
    u_int th_ack;         // acknowledge number
    u_int8_t th_offx2;   // data offset, reserved
    #define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_int8_t th_flags;
    u_int8_t th_win[2];
    u_int8_t th_sum[2];
    u_int8_t th_urp[2];

};

const struct sniff_ethernet *ethernet;
const struct sniff_ip *ip;
const struct sniff_tcp *tcp;

void printMacAddress(){
    printf("\n --- ethernet ---\n");
    printf("ethernet destination: %02x:%02x:%02x:%02x:%02x:%02x\n",
          ethernet->dhost[0],ethernet->dhost[1],ethernet->dhost[2],ethernet->dhost[3],ethernet->dhost[4],ethernet->dhost[5]);
    printf("ethernet source: %02x:%02x:%02x:%02x:%02x:%02x\n",
          ethernet->shost[0],ethernet->shost[1],ethernet->shost[2],ethernet->shost[3],ethernet->shost[4],ethernet->shost[5]);
}

void printIpAddress(){
    printf("\n --- ip ---\n");
    printf("ip destination: %d.%d.%d.%d\n",ip->dhost[0],ip->dhost[1],ip->dhost[2],ip->dhost[3]);
    printf("ip source: %d.%d.%d.%d\n",ip->shost[0],ip->shost[1],ip->shost[2],ip->shost[3]);
}

void printTcpPort(){
    printf("\n --- tcp ---\n");
    printf("tcp destination port: %d\n", tcp->dport[0]*256 + tcp->dport[1]);
    printf("tcp source port: %d\n", tcp->sport[0]*256 + tcp->sport[1]);

}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}


#endif // PCAP_TEST_H
