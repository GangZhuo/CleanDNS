#ifndef CLEANDNS_NS_MSG_H_
#define CLEANDNS_NS_MSG_H_

#include <stdint.h>
#ifdef WINDOWS
#include "../windows/win.h"
#else
#include <arpa/inet.h>
#endif

#include "stream.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NS_PAYLOAD_SIZE		1024
#define NS_LABEL_SIZE		63
#define NS_NAME_SIZE		255
#define NS_QNAME_SIZE		NS_NAME_SIZE
#define NS_EDNS_VERSION		0
#define NS_MAX_LABEL_COUNT	512

#define NS_QTYPE_A			1
#define NS_QTYPE_NS			2
#define NS_QTYPE_MD			3
#define NS_QTYPE_MF			4
#define NS_QTYPE_CNAME		5
#define NS_QTYPE_SOA		6
#define NS_QTYPE_MB			7
#define NS_QTYPE_MG			8
#define NS_QTYPE_MR			9
#define NS_QTYPE_NULL		10
#define NS_QTYPE_WKS		11
#define NS_QTYPE_PTR		12
#define NS_QTYPE_HINFO		13
#define NS_QTYPE_MINFO		14
#define NS_QTYPE_MX			15
#define NS_QTYPE_TXT		16
#define NS_QTYPE_AAAA		28	
#define NS_QTYPE_OPT		41
#define NS_QTYPE_AXFR		252
#define NS_QTYPE_MAILB		253
#define NS_QTYPE_MAILA		254
#define NS_QTYPE_ANY		255

#define NS_QCLASS_IN		1		
#define NS_QCLASS_CS		2		
#define NS_QCLASS_CH		3		
#define NS_QCLASS_HS		4		
#define NS_QCLASS_ANY		255

#define NS_TYPE_A			NS_QTYPE_A		
#define NS_TYPE_NS			NS_QTYPE_NS		
#define NS_TYPE_MD			NS_QTYPE_MD		
#define NS_TYPE_MF			NS_QTYPE_MF		
#define NS_TYPE_CNAME		NS_QTYPE_CNAME	
#define NS_TYPE_SOA			NS_QTYPE_SOA		
#define NS_TYPE_MB			NS_QTYPE_MB		
#define NS_TYPE_MG			NS_QTYPE_MG		
#define NS_TYPE_MR			NS_QTYPE_MR		
#define NS_TYPE_NULL		NS_QTYPE_NULL	
#define NS_TYPE_WKS			NS_QTYPE_WKS		
#define NS_TYPE_PTR			NS_QTYPE_PTR		
#define NS_TYPE_HINFO		NS_QTYPE_HINFO	
#define NS_TYPE_MINFO		NS_QTYPE_MINFO	
#define NS_TYPE_MX			NS_QTYPE_MX		
#define NS_TYPE_TXT			NS_QTYPE_TXT		
#define NS_TYPE_AAAA		NS_QTYPE_AAAA	
#define NS_TYPE_OPT			NS_QTYPE_OPT		

#define NS_CLASS_IN			NS_QCLASS_IN
#define NS_CLASS_CS			NS_QCLASS_CS
#define NS_CLASS_CH			NS_QCLASS_CH
#define NS_CLASS_HS			NS_QCLASS_HS

#define NS_OPTCODE_ECS      8 /* edns-client-subnet */

#define ADDR_FAMILY_NUM_IP  1 /*IPv4*/
#define ADDR_FAMILY_NUM_IP6 2 /*IPv6*/

typedef struct ns_hinfo_t {
	char *cpu;
	char *os;
} ns_hinfo_t;

typedef struct ns_minfo_t {
	char *rmailbx;
	char *emailbx;
} ns_minfo_t;

typedef struct ns_mx_t {
    uint16_t preference;
    char *exchange;
} ns_mx_t;

typedef struct ns_soa_t {
	char *mname;
	char *rname;
	uint32_t serial;
	uint32_t refresh;
	uint32_t retry;
	uint32_t expire;
	uint32_t minimum;
} ns_soa_t;

typedef struct ns_opt_t {
	uint16_t code;
	uint16_t length;
	void *data;
} ns_opt_t;

typedef struct ns_edns_t {
    ns_opt_t *opts;
    int optcount;
} ns_edns_t;

typedef struct ns_rr_t {
	char *name;
	uint16_t type;
	uint16_t cls; /* class */
	uint32_t ttl;
	uint16_t rdlength;
	void *rdata;
} ns_rr_t;

typedef struct ns_qr_t {
	char *qname;
	uint16_t qtype;
	uint16_t qclass;
} ns_qr_t;

typedef struct ns_msg_t {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;

	ns_qr_t *qrs;
	ns_rr_t *rrs;
} ns_msg_t;

int init_ns_msg(ns_msg_t *msg);
void ns_msg_free(ns_msg_t *msg);

int ns_parse(ns_msg_t *msg, uint8_t *bytes, int nbytes);

ns_rr_t *ns_find_rr(ns_msg_t *msg, int type);

#define ns_find_edns(msg) \
	ns_find_rr((msg), NS_TYPE_OPT)

ns_rr_t *ns_add_edns(ns_msg_t *msg);

int ns_remove_edns(ns_msg_t *msg);

ns_opt_t *ns_edns_find_ecs(ns_rr_t *rr);

int ns_edns_set_ecs(ns_rr_t *rr, struct sockaddr *addr, int srcprefix, int scopeprefix);

int ns_serialize(stream_t *s, ns_msg_t *msg, int compression);

void ns_print(ns_msg_t *msg);

const char *ns_typename(uint16_t type);

const char *ns_classname(uint16_t cls);

/* parse subnet like "192.168.1.1/24" */
int ns_ecs_parse_subnet(struct sockaddr *addr /*out*/, int *pmask /*out*/, const char *subnet /*in*/);

#define ns_flag_qr(msg) ((((msg)->flags) >> 15) & 1)
#define ns_flag_opcode(msg) ((((msg)->flags) >> 11) & 0xf)
#define ns_flag_aa(msg) ((((msg)->flags) >> 10) & 1)
#define ns_flag_tc(msg) ((((msg)->flags) >> 9) & 1)
#define ns_flag_rd(msg) ((((msg)->flags) >> 8) & 1)
#define ns_flag_ra(msg) ((((msg)->flags) >> 7) & 1)
#define ns_flag_z(msg) ((((msg)->flags) >> 4) & 7)

static inline int ns_flag_rcode(ns_msg_t *msg)
{
    int rcode = (msg->flags) & 0xf;
    ns_rr_t *rr = ns_find_edns(msg);
    if (rr) {
        rcode |= (rr->ttl >> 20) & 0xff00;
    }
    return rcode;
}

#define ns_is_edns_rr(rr) ((rr)->type == NS_QTYPE_OPT)

#define ns_rrcount(msg) ((msg)->ancount + (msg)->nscount + (msg)->arcount)

#ifdef __cplusplus
}
#endif

#endif /*CLEANDNS_NS_MSG_H_*/
