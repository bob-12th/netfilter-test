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

char* banned_host;

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	unsigned char *payload;
	int flag = NF_ACCEPT;

	printf("entering callback\n");

	nfq_get_payload(nfa ,&payload);

	printf("%02x \n",payload[40]);

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

				char *host = (char *)malloc(host_len + 1);
                strncpy(host, start_of_host, host_len);
                host[host_len] = '\0';

				printf("Extracted Host: %s\n", host);
				

				if( strcmp(host, banned_host) == 0)
				{
					flag = NF_DROP;
					printf("[*] %s is blocked..\n",host);
				}
				free(host);
			}
		}
	}
	return nfq_set_verdict(qh, id, flag, 0, NULL);
}

void setIptables()
{
	printf("[*] execute \"sudo iptables -F\"\n");
	system("sudo iptables -F");

	printf("[*] execute \"sudo iptables -A OUTPUT -j NFQUEUE\n");
    system("sudo iptables -A OUTPUT -j NFQUEUE");

	printf("[*] execute \"sudo iptables -A INPUT -j NFQUEUE\n");
    system("sudo iptables -A INPUT -j NFQUEUE");
}

void resetIptables()
{
	printf("[*] execute \"sudo iptables -F\"\n");
	system("sudo iptables -F");
}

int main(int argc, char **argv)
{
	setIptables();

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	banned_host = argv[1];

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		setIptables();
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
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
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
		resetIptables();
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

