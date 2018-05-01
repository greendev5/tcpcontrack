#include <stdio.h>
#include <arpa/inet.h>

#include "uthash.h"
#include "tct_logger.h"
#include "tct.h"

/*  */
#define TCT_FLAG_SYN 0x02

/* Internal types */

typedef struct tct_htable_node
{
	tct_ipv4_tuple_t key;
	tct_stream_t stream;
	UT_hash_handle hh;
} tct_htable_node_t;


typedef struct
{
	tct_htable_node_t *active_streams;
} tct_session_ctx_t;

/* Static methods */

static tct_htable_node_t* find_active_stream_node(tct_session_ctx_t* ctx, const tct_ipv4_tuple_t *tuple)
{
	tct_ipv4_tuple_t tmp;
	tct_htable_node_t *node = NULL;

	HASH_FIND(hh, ctx->active_streams, tuple, sizeof(tct_ipv4_tuple_t), node);
	if (!node) {
		memset(&tmp, 0, sizeof(tct_ipv4_tuple_t));
		tmp.protocol = 4;
		tmp.source[0] = tuple->destination[0];
		tmp.destination[0] = tuple->source[0];
		tmp.sport = tuple->dport;
		tmp.dport = tuple->sport;
		HASH_FIND(hh, ctx->active_streams, &tmp, sizeof(tct_ipv4_tuple_t), node);
	}
	return node;
}

static tct_htable_node_t* create_active_stream_node(tct_session_ctx_t* ctx, const tct_ipv4_tuple_t *tuple)
{
	tct_htable_node_t *node = (tct_htable_node_t*)malloc(sizeof(tct_htable_node_t));
	memset(node, 0, sizeof(tct_htable_node_t));
	memcpy(&(node->key), tuple, sizeof(tct_ipv4_tuple_t));
	node->stream.state = TCT_STREAM_SENT_SYN;
	node->stream.tuple = &(node->key);
	HASH_ADD(hh, ctx->active_streams, key, sizeof(tct_ipv4_tuple_t), node);
	return node;
}

static const char* packet_to_str(const struct ip *ip4hdr, const struct tcphdr *tcp)
{
	/* We are running a single thread - it is quite safe*/
	static char buf[128] = {0};
	char src[INET_ADDRSTRLEN];
	char dst[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &(ip4hdr->ip_src), src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip4hdr->ip_dst), dst, INET_ADDRSTRLEN);

	snprintf(
			buf, sizeof(buf) - 1, "%s:%d -> %s:%d [fin=%d syn=%d, rst=%d, psh=%d, ack=%d, urg=%d]",
			src, ntohs((uint16_t)tcp->th_sport),
			dst, ntohs((uint16_t)tcp->th_dport),
			tcp->fin, tcp->syn, tcp->rst, tcp->psh, tcp->ack, tcp->urg);
	return buf;
}

static const char* tuple_to_str(const tct_ipv4_tuple_t *tuple)
{
	/* We are running a single thread - it is quite safe*/
	static char buf[64] = {0};
	char src[INET_ADDRSTRLEN];
	char dst[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &(tuple->source[0]), src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(tuple->destination[0]), dst, INET_ADDRSTRLEN);

	snprintf(
			buf, sizeof(buf) - 1, "%s:%d -> %s:%d",
			src, tuple->sport,
			dst, tuple->dport);
	return buf;
}

static int process_stream_packet(
		tct_session_ctx_t *ctx, tct_htable_node_t *node, const struct ip *iphdr, const struct tcphdr *tcp)
{
	int ret = TCT_SUCCESS;

	if (node->stream.state == TCT_STREAM_SENT_SYN) {

		if (tcp->syn && tcp->ack) {
			node->stream.state = TCT_STREAM_SENT_SYN_ACK;
			TCT_LOGGER_DEBUG("Received SYN/ACK: %s", packet_to_str(iphdr, tcp));
		} else if (tcp->syn) {
			node->stream.syn_retries++;
			TCT_LOGGER_DEBUG("Resent SYN: %s", packet_to_str(iphdr, tcp));
		} else if (tcp->rst) {
			node->stream.state = TCT_STREAM_FAILED;
			TCT_LOGGER_DEBUG("Connection was rejected during establishing: %s", packet_to_str(iphdr, tcp));
		} else {
			TCT_LOGGER_ERROR("Strange packet: %s", packet_to_str(iphdr, tcp));
		}

	} else if (node->stream.state == TCT_STREAM_SENT_SYN_ACK) {

		if (tcp->rst) {
			node->stream.state = TCT_STREAM_FAILED;
			TCT_LOGGER_DEBUG("Connection was rejected during establishing: %s", packet_to_str(iphdr, tcp));
		} else if (tcp->ack) {
			node->stream.state = TCT_STREAM_ESTABLISHED;
			TCT_LOGGER_DEBUG("Connection was established: %s", packet_to_str(iphdr, tcp));
		}else {
			TCT_LOGGER_ERROR("Strange packet: %s", packet_to_str(iphdr, tcp));
		}

	} else if (node->stream.state == TCT_STREAM_ESTABLISHED) {

		if (tcp->rst) {
			node->stream.state = TCT_STREAM_DROPPED;
			TCT_LOGGER_DEBUG("Connection was droped: %s", packet_to_str(iphdr, tcp));
		} else if (tcp->fin) {
			node->stream.state = TCT_STREAM_CLOSED;
			TCT_LOGGER_DEBUG("Connection was closed: %s", packet_to_str(iphdr, tcp));
		}
	}

	return ret;
}

/* Public interface */

int tct_init(tct_session_t *session)
{
	tct_session_ctx_t *ctx = (tct_session_ctx_t*)malloc(sizeof(tct_session_t));
	if (!ctx) {
		return TCT_ERROR_UNKNOWN;
	}
	memset(ctx, 0, sizeof(tct_session_ctx_t));
	*session = (tct_session_t)ctx;
	return TCT_SUCCESS;
}

void tct_free(tct_session_t session)
{
	tct_session_ctx_t *ctx = (tct_session_ctx_t*)session;
	/* TODO: do correct clean up */
	free(ctx);
}

int tct_process_ipv4_packet(tct_session_t session, struct ip *iphdr, size_t len)
{
	int ret = TCT_SUCCESS;
	struct tcphdr *tcp = (struct tcphdr*)((uint8_t*)iphdr + iphdr->ip_hl * 4);
	tct_session_ctx_t *ctx = (tct_session_ctx_t*)session;
	tct_htable_node_t *node;
	tct_ipv4_tuple_t tuple;

	tct_fill_ipv4_tuple(iphdr, tcp, &tuple);
	node = find_active_stream_node(ctx, &tuple);

	if (node) {
		return process_stream_packet(ctx, node, iphdr, tcp);
	} else {
		if (tcp->th_flags == TCT_FLAG_SYN) {
			create_active_stream_node(ctx, &tuple);
			TCT_LOGGER_DEBUG("Detected new TCP connection SYN: %s", packet_to_str(iphdr, tcp));
		} else {
			TCT_LOGGER_DEBUG("Packet from unknown stream: %s", packet_to_str(iphdr, tcp));
		}
	}

	return ret;
}


int tct_fill_ipv4_tuple(const struct ip *ip4hdr, const struct tcphdr *tcp, tct_ipv4_tuple_t *tuple)
{
	memset(tuple, 0, sizeof(tct_ipv4_tuple_t));
	tuple->protocol = 4;
	tuple->source[0] = ip4hdr->ip_src.s_addr;
	tuple->destination[0] = ip4hdr->ip_dst.s_addr;
	tuple->sport = ntohs((uint16_t)tcp->th_sport);
	tuple->dport = ntohs((uint16_t)tcp->th_dport);
	return TCT_SUCCESS;
}

tct_stream_t* tct_find_stream(tct_session_t session, const tct_ipv4_tuple_t *tuple)
{
	tct_session_ctx_t *ctx = (tct_session_ctx_t*)session;
	tct_htable_node_t *node;

	HASH_FIND(hh, ctx->active_streams, tuple, sizeof(tct_ipv4_tuple_t), node);
	if (node) {
		return &(node->stream);
	}

	return NULL;
}

void tct_print_report(tct_session_t session)
{
	tct_session_ctx_t *ctx = (tct_session_ctx_t*)session;
	tct_htable_node_t *node;

	printf("\n     REPORT    \n\n");

	for (node = ctx->active_streams; node != NULL; node = (tct_htable_node_t*)(node->hh.next)) {
		printf("----------------\n");
		printf("%s\n", tuple_to_str(node->stream.tuple));
		if (node->stream.state == TCT_STREAM_SENT_SYN) {
			if (node->stream.syn_retries > 0) {
				printf("CONNECTION FAILED (%d SYN retries detected. Probably FAILED)\n", node->stream.syn_retries);
			} else {
				printf("ESTABLISHING CONNECTION\n");
			}
		} else if (node->stream.state == TCT_STREAM_SENT_SYN_ACK) {
			printf("ESTABLISHING CONNECTION\n");
		} else if (node->stream.state == TCT_STREAM_ESTABLISHED) {
			printf("CONNECTION ESTABLISHED\n");
		} else if (node->stream.state == TCT_STREAM_CLOSED) {
			printf("CONNECTION CLOSED\n");
		} else if (node->stream.state == TCT_STREAM_DROPPED) {
			printf("CONNECTION DROPPED (reset packet was sent)\n");
		} else if (node->stream.state == TCT_STREAM_FAILED) {
			printf("CONNECTION FAILED (reset packet was sent)\n");
		}
	}
}
