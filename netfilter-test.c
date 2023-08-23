#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>  
#include <string.h>
#include <signal.h>

char* malicious_host;
int ctrlC = 0;

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}


/* returns packet id */
// unused
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d\n", ret);

	fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = ntohl((nfq_get_msg_packet_hdr(nfa))->packet_id);
	unsigned char *payload;
	int flag = NF_ACCEPT;

//	printf("entering callback\n");

	int payload_len = nfq_get_payload(nfa ,&payload);
	
	// use ip/tcp header to access http header
	struct iphdr *ip_header = (struct iphdr *)payload;
	struct tcphdr *tcp_header = (struct tcphdr *)(payload + ip_header->ihl * 4);

	int tcp_header_len = tcp_header->doff * 4;

	unsigned char *tcp_payload = payload + ip_header->ihl * 4 + tcp_header_len;

	if (ntohs(tcp_header->dest) == 80) {
		char *http_header = (char *)tcp_payload;
		char *start_of_host = strstr(http_header, "Host:");
		if (start_of_host != NULL) {
			start_of_host += strlen("Host: ");
			
			char *end_of_host = strchr(start_of_host, '\r');
			if (end_of_host != NULL) {
				int host_len = end_of_host - start_of_host;
				printf("host len : %d\n",host_len);

				printf("[*] extracted host from  pkt : %s\n", start_of_host);
				start_of_host[host_len] = '\0';
				if( strncmp(start_of_host, malicious_host, host_len) == 0)
				{
					flag = NF_DROP;
					printf("[*] %s is blocked..\n",start_of_host);
				}
			}
		}
	}
	return nfq_set_verdict(qh, id, flag, 0, NULL);
}

// for queue
void setIptables()
{
	printf("[*] execute \"sudo iptables -F\"\n");
	system("sudo iptables -F");

	printf("[*] execute \"sudo iptables -A OUTPUT -j NFQUEUE  --queue-num 0\n");
    system("sudo iptables -A OUTPUT -j NFQUEUE");

	printf("[*] execute \"sudo iptables -A INPUT -j NFQUEUE  --queue-num 0\n");
    system("sudo iptables -A INPUT -j NFQUEUE");
}

void resetIptables()
{
	printf("[*] execute \"sudo iptables -F\n");
    system("sudo iptables -F");
}

void sig_handler(int signal)
{
	if (signal == SIGINT) {
        ctrlC = 1;  // Set the flag indicating Ctrl+C was pressed
        resetIptables();   // Call the resetIptables function
        printf("[*] Ctrl+C pressed. stop program...\n");
        exit(0);  // Exit the program
    }
}


int main(int argc, char **argv)
{
	signal(SIGINT, sig_handler);
	
	setIptables();

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	
	// set dangerous host
	malicious_host = argv[1];

	printf("[*] opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "[*] error during nfq_open()\n");
		exit(1);
	}

	printf("[*] unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "[*] error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("[*] binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "[*] error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("[*] binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "[*] error during nfq_create_queue()\n");
		exit(1);
	}

	printf("[*] setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "[*] can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if (ctrlC)
		{
			break;
		}

		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
	//		printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("[*] losing packets!\n");
			continue;
		}
		perror("[*] recv failed");
		break;
	}

	printf("[*] unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("[*] unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("[*] closing library handle\n");
	nfq_close(h);

	exit(0);
}

