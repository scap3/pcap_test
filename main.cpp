#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define SIZE_ETHERNET 14	/* ethernet header are always exactly 14 bytes */
#define ETHER_ADDR_LEN 6	/* Ethernet addresses are 6 bytes */
#define ETHERTYPE_IP 0x0800

struct sniff_ethernet{
	u_char ether_dhost[ETHER_ADDR_LEN];	/* Destination MAC Address */
	u_char ether_shost[ETHER_ADDR_LEN];	/* Source MAC Address */
	u_short ether_type;	/* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip{
	u_char ip_vhl;		/* version <<4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000	/* reserved fragment flag */
	#define IP_DF 0x4000	/* dont fragment flag */
	#define IP_MF 0x2000	/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/*mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst;	/* Source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->up_vhl) >> 4)

/* tcp header */
typedef u_int tcp_seq;

struct sniff_tcp{
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

void usage(){
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]){
	if (argc != 2){
		usage();
		return -1;
	}
	char *dev=argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if (handle == NULL){
		fprintf(stderr, "couldn't open device %s: %s\n",dev,errbuf);
		return -1;
	}
	const struct sniff_ethernet *etherhd;		/* The ethernet header */
	const struct sniff_ip *iphd;			/* The IP header */
	const struct sniff_tcp *tcphd;			/* The TCP header */
	const char *payload;				/* Packet payload */
	u_int size_ip;
	u_int size_tcp;
	u_short ether_type;
	int i, payload_len;
	printf("[bob7][%s]pcap_test[%s]\n\n","포렌식","송병관");
	printf("----------------------------------------------------------------------\n\n");
  	while (1){
   		struct pcap_pkthdr* header;
	    	const u_char* packet;
	    	int res = pcap_next_ex(handle, &header, &packet);
    		
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		etherhd = (struct sniff_ethernet *)(packet);

		printf("Source MAC Address : ");
		for (i=0; i<ETHER_ADDR_LEN; i++){
			printf("%02x ", etherhd->ether_shost[i]);
		}
		printf("\nDestination MAC Address : ");
		for (i=0; i<ETHER_ADDR_LEN; i++){
			printf("%02x ", etherhd->ether_dhost[i]);
		}
		ether_type = ntohs(etherhd->ether_type);

		if (ether_type == ETHERTYPE_IP){
			iphd = (struct sniff_ip *)(packet + SIZE_ETHERNET);
			size_ip = IP_HL(iphd) * 4;
			printf("\nSource IP Address : %s\n", inet_ntoa(iphd->ip_src));
			printf("Destination IP Address : %s\n", inet_ntoa(iphd->ip_dst));
			if (iphd->ip_p == IPPROTO_TCP){
				tcphd = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
				size_tcp = TH_OFF(tcphd)*4;

				printf("\nSource Port : %d\n", ntohs(tcphd->th_sport));
				printf("Destination Port : %d\n", ntohs(tcphd->th_dport));
				payload=(char*)(packet+SIZE_ETHERNET+size_ip+size_tcp);
				payload_len = ntohs(iphd->ip_len)-(size_ip + size_tcp);
				if (payload_len == 0)
					printf("\nNone PayLoad\n");
				else{
					printf("\nPayload Data : ");
					for (int i=1; i< payload_len; i++){
						printf("%02x ", payload[i-1]);
						if (i%16 == 0)  break;
					}
					printf("\n\n");
				}
			}
			else{
				printf("\nNone TCP Segment \n");
			}

		}
		else{
			printf("\nNone IP Packet \n");
		}
		printf("*********************************************************************\n");
	}
  	pcap_close(handle);
  	return 0;
}
