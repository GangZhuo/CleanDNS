#ifndef CLEANDNS_H_
#define CLEANDNS_H_

#ifdef WINDOWS
#include "../windows/win.h"
typedef SOCKET sock_t;
#else
#include <time.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
typedef int sock_t;
#endif

#define MAX_DNS_SERVER 8
#define MAX_NS_MSG (MAX_DNS_SERVER * 2)

#define CONN_CONNECTING			0
#define CONN_CONNECTED			1
#define CONN_PROXY_HANKSHAKE_1	2
#define CONN_PROXY_HANKSHAKE_2	3
#define CONN_PROXY_HANKSHAKE_3	4
#define CONN_PROXY_HANKSHAKE_4	5
#define CONN_PROXY_CONNECTED	6

#include "rbtree.h"
#include "ns_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct proxy_state_t {
	char *sendbuf;
	int sendbuf_size;
} proxy_state_t;

typedef struct conn_t {
	sock_t sock;
	int status;
	int dns_server_index;
	int by_proxy;
	proxy_state_t *proxy_state;
	char* sendbuf;
	int sendbuf_size;
	char *recvbuf;
	int recvbuf_size;
} conn_t;

typedef struct req_t {
	uint16_t id;
    uint16_t old_id;
	char *questions;
    int edns;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	time_t expire;
	ns_msg_t ns_msg[MAX_NS_MSG];
	int ns_msg_num;
	int wait_num;
	conn_t conns[MAX_NS_MSG];
	int conn_num;
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

typedef struct dns_server_t {
	struct addrinfo* addr;
	int is_foreign;
	int tcp;
} dns_server_t;

typedef struct proxy_server_t {
	struct addrinfo *addr;
} proxy_server_t;

typedef struct cleandns_ctx {
	char *listen_addr;
	char *listen_port;
	char *dns_server;
	char *chnroute_file;
	char *china_ip;
	char *foreign_ip;
	int compression;
	int timeout;
	char* pid_file;
	char* log_file;
	int daemonize;
    int lazy;
	char *proxy;
	net_list_t chnroute_list;
	dns_server_t dns_servers[MAX_DNS_SERVER];
	int dns_server_num;
	subnet_t china_net;
	subnet_t foreign_net;
	sock_t listen_sock;
	sock_t remote_sock;
	char buf[NS_PAYLOAD_SIZE];
	rbtree_t queue;
	proxy_server_t proxy_server;
} cleandns_ctx;

#ifdef __cplusplus
}
#endif

#endif /*CLEANDNS_H_*/
