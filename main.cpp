#include "pcap_test.h"
#include <pcap.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
}


  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;


    u_char *payload;

    u_int size_ip;
    u_int size_tcp;

    ethernet = (struct sniff_ethernet*)(packet);
    printMacAddress();

    if( (ethernet->type[0]*256 + ethernet->type[1]) == 2048){ // 0x0800 == ip protocol
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    printIpAddress();

    #define IP_HL(ip)		(((ip)->vhl) & 0x0f)
    #define IP_V(ip)		(((ip)->vhl) >> 4)

    size_ip = IP_HL(ip)*4;

    if (size_ip < 20){
        printf("Invalid IP header length: %u bytes\n\n\n", size_ip);
        continue;
    }
    if(ip->p == 6) // when tcp protocol (6)
    {
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

        size_tcp = TH_OFF(tcp)*4;

        u_int totallength = ip->len[0]*256 + ip->len[1] - size_ip - size_tcp;


        if (size_tcp < 20) {
             printf("Invalid TCP header length: %u bytes\n\n\n", size_tcp);
             continue;
            }

        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);


        printTcpPort();

        if(totallength<=0){
            printf("\n\nNo payload\n\n\n");
            continue;
        }
        if((0<totallength) && (totallength<=10)){
            printf("\n\n --- payload ---\n ");
            for(int i=0; i<totallength; i++){
                 printf("%c",payload[i]);
            }
            printf("\n\n\n");
          }

        if(totallength>10){
            printf("\n\n --- payload ---\n ");
            for(int i=0; i<10; i++){
                printf("%c",payload[i]);
            }
            printf("\n\n\n");
        }

    }
    else {
        printf("Not TCP protocol\n\n\n");
        continue;
    }

  }
}
  pcap_close(handle);
  return 0;
}
