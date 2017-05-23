#ifndef CLEANDNS_H_
#define CLEANDNS_H_

#ifdef WINDOWS
#include "../windows/win.h"
#else
#include <time.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#endif

#include "rbtree.h"
#include "ns_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct req_t {
	uint16_t id;
    uint16_t old_id;
    int edns;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	time_t expire;
	ns_msg_t *ns_msg;
} req_t;

typedef struct subnet_t {
	const char *name;
	struct sockaddr_storage addr;
	int mask;
} subnet_t;

typedef struct net_mask_t {
	uint32_t net;
	uint32_t mask;
} net_mask_t;

typedef struct net_list_t {
	int entries;
	net_mask_t *nets;
} net_list_t;

typedef struct cleandns_ctx {
	char *listen_addr;
	char *listen_port;
	char *dns_server;
	char *chnroute_file;
	char *china_ip;
	char *foreign_ip;
	int compression;
	int timeout;
	net_list_t chnroute_list;
	struct addrinfo *dns_server_addr;
	subnet_t china_net;
	subnet_t foreign_net;
	int listen_sock;
	int remote_sock;
	char buf[NS_PAYLOAD_SIZE];
	rbtree_t queue;
} cleandns_ctx;

#ifdef __cplusplus
}
#endif

#endif /*CLEANDNS_H_*/
