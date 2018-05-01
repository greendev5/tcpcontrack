#ifndef TCT_CONTAINER
#define TCT_CONTAINER

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#ifndef IP4_ADDR_LEN
# define IP4_ADDR_LEN 4
#endif
#ifndef IP4_HEADER_LEN
# define IP4_HEADER_LEN 20
#endif

typedef void* tct_session_t;

typedef enum tct_err {
	TCT_SUCCESS = 0,
	TCT_ERROR_UNKNOWN = -17
} tct_err_t;

/* For now I do not want to spanet time on
 * processing every possible TCP scenario. */
typedef enum tct_stream_state
{
	TCT_STREAM_SENT_SYN=0,   /* */
	TCT_STREAM_SENT_SYN_ACK, /* */
	TCT_STREAM_ESTABLISHED,  /* */
	TCT_STREAM_CLOSED,       /* */
	TCT_STREAM_DROPPED,      /* */
	TCT_STREAM_FAILED,       /* */
} tct_stream_state_t;

typedef struct {
	uint32_t source[IP4_ADDR_LEN];
	uint32_t destination[IP4_ADDR_LEN];
	uint16_t sport;
	uint16_t dport;
	uint8_t  protocol;
} tct_ipv4_tuple_t;

typedef struct {
	tct_stream_state_t state;
	uint16_t syn_retries;
	const tct_ipv4_tuple_t *tuple;
} tct_stream_t;

int tct_init(tct_session_t *session);

void tct_free(tct_session_t session);

int tct_process_ipv4_packet(tct_session_t session, struct ip *iphdr, size_t len);

tct_stream_t* tct_find_stream(tct_session_t session, const tct_ipv4_tuple_t *tuple);

int tct_fill_ipv4_tuple(const struct ip *ip4hdr, const struct tcphdr *tcp, tct_ipv4_tuple_t *tuple);

/* TODO: provide an interator object for calling code */
void tct_print_report(tct_session_t session);

#endif
