#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <netinet/ip.h>

#include <pcap/pcap.h>

#include <tct_version_no.h>
#include "tct_logger.h"
#include "tct.h"

/// macro to verify if an IP datagram is part of a fragmented datagram
/// stolen from libntoh
#define NTOH_IPV4_IS_FRAGMENT(off)	( ( (8*(ntohs(off) & 0x1FFF)) > 0 || (ntohs(off) & 0x2000) ) && !(ntohs(off) & 0x4000) )

/// We process .pcap files only, lets check it
#define SLL_HEADER_LEN 16

/* Static Variables */
static char tct_pcap_errbuf[PCAP_ERRBUF_SIZE];
static tct_session_t session = NULL;

static void print_version(const char *app)
{
	printf(
		"%s %s by Illia Muzychuk\n"
		"This version does not support live capturing. \n"
		"Only .pcap files analise is supported.\n",
		app, PRODUCTVERSTR_DOT
	);
}

static void print_usage(const char *app)
{
	printf(
		"Usage: %s [-vh] -R <pcap_input>\n",
		app
	);
}

static void parse_opts(int argc, char *argv[], char **input)
{
	int opt = 0;
	*input = NULL;

	while ((opt = getopt(argc, argv, "hvR:")) > 0) {
		switch (opt) {
			case 'v':
				print_version(argv[0]);
				exit(EXIT_SUCCESS);
			case 'h':
				print_usage(argv[0]);
				exit(EXIT_SUCCESS);
			case 'R':
				*input = optarg;
				break;
			default:
				print_usage(argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	if (!*input) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}
}

/*
 * This idea of this method is no setup filter,
 * which will skip non IP packets, e.g ARP
 */
static bool configure_tct_pcap(pcap_t *ph)
{
	struct bpf_program filter;
	const char *filter_app = "ip";

	if (pcap_compile(ph, &filter, filter_app, 0, 0) != 0) {
		fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(ph));
		return false;
	}

	if (pcap_setfilter(ph, &filter) != 0) {
		pcap_freecode(&filter);
		fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(ph));
		return false;
	}

	pcap_freecode(&filter);
	return true;
}

static void handle_pcap_packet(u_char *other, const struct pcap_pkthdr *header, const u_char *packet)
{
	int r;
	struct ip *ip = NULL;

	ip = (struct ip*)(packet + SLL_HEADER_LEN);

	/* I know that file contains mosltly TCP packets */
	/* But I wanted to be sure that there is no IP fragmentation */
	if (NTOH_IPV4_IS_FRAGMENT(ip->ip_off)) {
		TCT_LOGGER_DEBUG("Got IP FRAGMENT packet - Skipped");
		return;
	} else if (ip->ip_v == 6) {
		TCT_LOGGER_DEBUG("Got IPv6 packet - Skipped");
		return;
	} else if (ip->ip_p == IPPROTO_UDP) {
		TCT_LOGGER_DEBUG("Got UDP packet - Skipped");
		return;
	} else if (ip->ip_p != IPPROTO_TCP) {
		TCT_LOGGER_DEBUG("Got UNKNOWN packet - Skipped");
	}

	if (header->caplen < SLL_HEADER_LEN + IP4_HEADER_LEN)
		return;

	r = tct_process_ipv4_packet(
			session, ip, header->caplen - SLL_HEADER_LEN);
	if (r != TCT_SUCCESS) {
		TCT_LOGGER_ERROR("tct_process_ipv4_packet failed with code %d. Continue processing packets...", r);
	}
}

int main(int argc, char *argv[])
{
	char *input;
	pcap_t *ph = NULL;

	parse_opts(argc, argv, &input);

	ph = pcap_open_offline(input, tct_pcap_errbuf);
	if (!ph) {
		fprintf(stderr, "pcap_open_offline failed: %s\n", tct_pcap_errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_datalink(ph) != DLT_LINUX_SLL) {
		fprintf(stderr, "Unknown captured traffic format from %s \n", input);
		goto pcap_error;
	}

	if (!configure_tct_pcap(ph))
		goto pcap_error;

	if (tct_init(&session) != TCT_SUCCESS) {
		fprintf(stderr, "Could not create TCT session");
		goto pcap_error;
	}

	if (pcap_loop(ph, -1, handle_pcap_packet, NULL) == -1) {
		fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(ph));
		goto pcap_error;
	}

	tct_print_report(session);
	tct_free(session);
	pcap_close(ph);
	exit(EXIT_SUCCESS);

pcap_error:
	if (session)
		tct_free(session);
	pcap_close(ph);
	exit(EXIT_FAILURE);
}
