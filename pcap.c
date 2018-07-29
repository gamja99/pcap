#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <algorithm>


int main(int argc, char* argv[]) 
{
	if (argc != 2) 
	{
		usage();
		return -1;
	}

	char* Dev = argv[1];
	char ebuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open(Dev, BUFSIZ, 1, 1000, ebuf);
	if (handle == NULL) 
	{
		fprintf(stderr, "Error %s: %s\n", Dev, ebuf);
		return -1;
	}

	while (true) 
	{
		struct pcap_pkthdr* header;
		const u_char* buf;

		ether_header* eh;

		int res = pcap_next_ex(handle, &header, &buf);
		if (res == 0) 
			continue;
		if (res == -1 || res == -2) 
			break;

		eh = (ether_header *)buf;


		printf("dst MAC: ");
		for (int i = 0; i<6; i++) 
			printf("%02X%c", eh->ether_dhost[i], i<5 ? ':' : '\n');
	
		printf("src MAC: ");
		for (int i = 0; i<6; i++) 
			printf("%02X%c", eh->ether_shost[i], i<5 ? ':' : '\n');

		if (ntohs(eh->ether_type) == ETH_P_IP) 
		{
			iphdr* iph = (iphdr *)(buf + sizeof(ether_header));
			puts("IPv4");
			
			printf("\tsrc addr: %s\n", inet_ntoa(*(in_addr *)&iph->saddr));
			printf("\tdst addr: %s\n", inet_ntoa(*(in_addr *)&iph->daddr));

			if (iph->protocol == IPPROTO_TCP) 
			{
				tcphdr* tcph = (tcphdr *)(buf + sizeof(ether_header) + (iph->ihl << 2));
				
				printf("TCP \n");
				printf("\tsrc port: %d\n", tcph->th_sport);
				printf("\tdst port: %d\n", tcph->th_dport);
				
				const u_char* payload = buf + ETH_HLEN + (iph->ihl << 2) + (tcph->doff << 2);
				
				int payload_size = htons(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);
				
				printf("size : %d\n", payload_size);
				
				if (payload_size)
				{
					puts("------------Data-----------");
					for (int i = 0; i<std::min(payload_size, 16); i++)
						printf("%02x ", payload[i]); printf("\n");
				}
			}
			else if (iph->protocol == IPPROTO_ICMP) 
			{
				puts("ICMP ");
			}
			else if (iph->protocol == IPPROTO_UDP)
			{
				puts("User Datagram Protocol(UDP)");
			}
			else
			{
				puts("Unknown ip_type");
			}
		}
		else if (ntohs(eh->ether_type) == ETH_P_ARP)
		{
			puts("ARP");
		}
		else if (ntohs(eh->ether_type) == ETH_P_IPV6)
		{
			puts("IPv6");
		}
		else {
			puts("Unknown ether_type");
		}
		puts("--------------------------------------------------");

	}

	pcap_close(handle);
	
	return 0;
}
void usage() 
{
	printf("pcap_test <interface>\n");
	printf("pcap_test wlan0\n");
}