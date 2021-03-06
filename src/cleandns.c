#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

#ifndef WINDOWS
#include <signal.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <netinet/tcp.h>
#endif


#include "log.h"
#include "cleandns.h"
#include "ns_msg.h"
#include "stream.h"
#include "dllist.h"

#define CLEANDNS_NAME    "CleanDNS"
#define CLEANDNS_VERSION "0.4.5"

#define DEFAULT_DNS_SERVER "8.8.8.8:53,114.114.114.114:53"
#define DEFAULT_LISTEN_ADDR "0.0.0.0"
#define DEFAULT_LISTEN_PORT "5354"
#define DEFAULT_CHNROUTE_FILE "chnroute.txt"
#define DEFAULT_TIMEOUT "5"
#define DEFAULT_PID_FILE "/var/run/cleandns.pid"
#define LISTEN_BACKLOG	128

#define FLG_NONE		0
#define FLG_POLLUTE		1
#define FLG_A			(1 << 1)
#define FLG_A_CHN		(1 << 2)
#define FLG_AAAA		(1 << 3)
#define FLG_AAAA_CHN	(1 << 4)
#define FLG_PTR			(1 << 5)
#define FLG_OPT			(1 << 6)

#define MAX(a, b) (((a) < (b)) ? (b) : (a))

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef EINPROGRESS
#define EINPROGRESS EAGAIN
#endif

#ifndef WSAEWOULDBLOCK
#define WSAEWOULDBLOCK EINPROGRESS
#endif

#ifndef SO_EXCLUSIVEADDRUSE
#define SO_EXCLUSIVEADDRUSE SO_REUSEADDR
#endif

#define fix_reqid(pid, num) ((*(pid)) = ((*(pid)) / (2 * (num))) * (num) * 2)
#define ext_num(msgid, num) ((msgid) - (((msgid) / (2 * num) ) * (num) * 2))
#define is_foreign(msgid, num) (ext_num((msgid), (num)) >= (num))
#define dns_index(msgid, num) ((ext_num((msgid), (num)) >= (num)) ? (ext_num((msgid), (num)) - (num)) : (ext_num((msgid), (num))))
#define is_eagain(err) ((err) == EAGAIN || (err) == EINPROGRESS || (err) == EWOULDBLOCK || (err) == WSAEWOULDBLOCK)

typedef struct {
	time_t now;
	rbnode_list_t *expired_nodes;
	cleandns_ctx *cleandns;
} timeout_handler_ctx;

typedef struct {
	rbnode_list_t* nodes;
	cleandns_ctx* cleandns;
} req_list_t;

typedef struct chnroute_item_t {
	dlitem_t entry;
	int is_ipv6;
	union {
		net_mask_t net;
		net_mask6_t net6;
	};
} chnroute_item_t;

typedef struct chnroute_list_t {
	dllist_t items;
	int net_num;
	int net6_num;
} chnroute_list_t;

static int running = 0;
static int is_use_syslog = 0;
static const char* log_file = NULL;

#ifdef WINDOWS

static cleandns_ctx* s_cleandns = NULL;
static SERVICE_STATUS ServiceStatus = { 0 };
static SERVICE_STATUS_HANDLE hStatus = NULL;

static void ServiceMain(int argc, char** argv);
static void ControlHandler(DWORD request);
#define strdup(s) _strdup(s)

#endif

static void usage();
static int init_cleandns(cleandns_ctx *cleandns);
static void free_cleandns(cleandns_ctx *cleandns);
static void free_conn(conn_t* conn);
static void queue_remove_bynode(cleandns_ctx* cleandns, rbnode_t* n);
static int parse_args(cleandns_ctx *cleandns, int argc, char **argv);
static int read_config_file(cleandns_ctx* cleandns, const char* config_file, int force);
static int check_args(cleandns_ctx* cleandns);
static void print_args(cleandns_ctx* cleandns);
static int parse_chnroute(cleandns_ctx *cleandns);
static int test_ip_in_list4(struct in_addr *ip, const net_list_t *netlist);
static int test_ip_in_list6(struct in6_addr* ip, const net_list_t* netlist);
static int test_addr_in_list(struct sockaddr* addr, const net_list_t* netlist);
static int resolve_listens(cleandns_ctx* cleandns);
static int resolve_dns_server(cleandns_ctx *cleandns);
static int init_listens(cleandns_ctx *cleandns);
static int init_dnsservers(cleandns_ctx* cleandns);
static int init_proxy_udpsock(cleandns_ctx* cleandns);
static int connect_server(cleandns_ctx* cleandns, conn_t* conn, dns_server_t* server);
static int tcp_send(cleandns_ctx* cleandns, conn_t* conn);
static int do_loop(cleandns_ctx *cleandns);
static int handle_listen_sock(cleandns_ctx *cleandns, listen_t* listen);
static int handle_remote_udprecv(cleandns_ctx *cleandns, dns_server_t* dnsserver,
	sock_t sock, proxy_server_t* proxyserver);
static int handle_remote_tcprecv(cleandns_ctx* cleandns, req_t* req, conn_t* conn, int conn_index);
static int response_best_nsmsg(cleandns_ctx* cleandns, req_t* req);
static char *get_addrname(struct sockaddr *addr);
static char *get_netaddrname(netaddr_t* addr);
static char* get_dnsservername(dns_server_t* dnsserver);
static int parse_netmask(net_mask_t *netmask, char *line);
static int resolve_proxy_server(cleandns_ctx* cleandns);
static void run_as_daemonize(cleandns_ctx* cleandns);
static void open_syslog();
static void close_syslog();
static void open_logfile();
static void close_logfile();
static int parse_china_ip(cleandns_ctx* cleandns);
static int parse_foreign_ip(cleandns_ctx* cleandns);

#ifdef WINDOWS
BOOL WINAPI sig_handler(DWORD signo)
{
	switch (signo) {
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	case CTRL_CLOSE_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:
		running = 0;
		break;
	default:
		break;
	}
	return TRUE;
}
#else
static void sig_handler(int signo) {
	if (signo == SIGINT)
		exit(1);  /* for gprof*/
	else
		running = 0;
}
#endif

int main(int argc, char **argv)
{
	cleandns_ctx cleandns = { 0 };

	memset(&cleandns, 0, sizeof(cleandns_ctx));

	if (rbtree_init(&cleandns.queue) != 0)
		return -1;

	srand((unsigned int)time(NULL));

#ifdef WINDOWS
	win_init();
	s_cleandns = &cleandns;
#endif

	if (parse_args(&cleandns, argc, argv) != 0)
		return EXIT_FAILURE;
	
	if (cleandns.daemonize) {
		run_as_daemonize(&cleandns);
		return EXIT_SUCCESS;
	}

#ifdef WINDOWS
	if (0 == SetConsoleCtrlHandler((PHANDLER_ROUTINE)sig_handler, TRUE)) {
		loge("can not set control handler\n");
		return EXIT_FAILURE;
	}
#else
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
#endif

	if (init_cleandns(&cleandns) != 0)
		return EXIT_FAILURE;

	print_args(&cleandns);

	if (do_loop(&cleandns) != 0)
		return EXIT_FAILURE;

	free_cleandns(&cleandns);

	if (log_file) {
		close_logfile();
	}

	if (is_use_syslog) {
		close_syslog();
	}

	return EXIT_SUCCESS;
}

static void print_args(cleandns_ctx* cleandns)
{
	int i;
	dns_server_t* dns_server;
	for (i = 0; i < cleandns->listen_num; i++) {
		logn("%s listen on %s\n",
			cleandns->listens[i].addr.protocol == IPPROTO_TCP ? "TCP" : "UDP",
			get_netaddrname(&cleandns->listens[i].addr));
	}
	logn("dns server:\n");
	for (i = 0; i < cleandns->dns_server_num; i++) {
		dns_server = cleandns->dns_servers + i;
		logn("  %d. '%s': %s%s%s\n",
			i + 1,
			get_dnsservername(dns_server),
			dns_server->is_foreign ? "foreign, " : "china, ",
			dns_server->is_foreign && cleandns->compression ? "compression, " : "",
			dns_server->addr.protocol == IPPROTO_TCP ? "TCP" : "UDP");
	}
	logn("chnroute: %s\n", cleandns->chnroute_file);
	logn("china ip: %s\n", cleandns->china_ip);
	logn("foreign ip: %s\n", cleandns->foreign_ip);
	logn("compression: %s\n", cleandns->compression ? "on" : "off");
	logn("pollution detection: %s\n", cleandns->lazy ? "off" : "on");
	logn("timeout: %d\n", cleandns->timeout);
	logn("loglevel: %d\n", loglevel);
	if (cleandns->proxy) {
		logn("proxy: %s\n", cleandns->proxy);
	}
#ifndef WINDOWS
	if (cleandns->daemonize) {
		logn("pid file: %s\n", cleandns->pid_file);
	}
#endif
	if (cleandns->log_file)
		logn("log_file: %s\n", cleandns->log_file);
}

static int cb_req_list(rbtree_t* tree, rbnode_t* x, void* state)
{
	req_list_t* ctx = state;
	req_t* req = x->info;

	rbnode_list_add(ctx->nodes, x);

	return 0;
}

static int do_loop(cleandns_ctx *cleandns)
{
	fd_set readset, writeset, errorset;
	sock_t max_fd;
	req_list_t req_list;
	rbnode_list_item_t* item;
	rbnode_t* n;
	req_t* req;
	int i;

	req_list.cleandns = cleandns;

	running = 1;
	while (running) {
		struct timeval timeout = {
			.tv_sec = 0,
			.tv_usec = 50 * 1000,
		};

		/* copy to a list, so can remove from queue in the while loop. */
		req_list.nodes = rbnode_list_create();

		if (req_list.nodes == NULL) {
			loge("do_loop(): rbnode_list_create() error\n");
			return -1;
		}

		rbtree_each(&cleandns->queue, cb_req_list, &req_list);

		FD_ZERO(&readset);
		FD_ZERO(&writeset);
		FD_ZERO(&errorset);

		max_fd = 0;

		for (i = 0; i < cleandns->listen_num; i++) {
			listen_t* listen = cleandns->listens + i;

			max_fd = MAX(max_fd, listen->sock);

			FD_SET(listen->sock, &readset);
			FD_SET(listen->sock, &errorset);
		}

		for (i = 0; i < cleandns->dns_server_num; i++) {
			dns_server_t* dnsserver = cleandns->dns_servers + i;

			if (!dnsserver->udpsock) continue;

			max_fd = MAX(max_fd, dnsserver->udpsock);

			FD_SET(dnsserver->udpsock, &readset);
			FD_SET(dnsserver->udpsock, &errorset);
		}

		if (cleandns->proxy_server.udpsock) {

			max_fd = MAX(max_fd, cleandns->proxy_server.udpsock);

			FD_SET(cleandns->proxy_server.udpsock, &readset);
			FD_SET(cleandns->proxy_server.udpsock, &errorset);
		}

		item = req_list.nodes->items;
		while (item) {
			n = item->node;
			req = n->info;
			item = item->next;

			if (req && req->conn_num > 0) {
				conn_t* conn;
				for (i = 0; i < req->conn_num; i++) {
					conn = req->conns + i;
					if (conn->sock <= 0)
						continue;

					if (max_fd < conn->sock)
						max_fd = conn->sock;

					FD_SET(conn->sock, &errorset);
					if (conn->sendbuf && conn->sendbuf_size > 0) {
						FD_SET(conn->sock, &writeset);
					}
					else {
						FD_SET(conn->sock, &readset);
					}
				}
			}
		}

		if (select((int)max_fd + 1, &readset, &writeset, &errorset, &timeout) == -1) {
			loge("do_loop() - select() error: errno=%d, %s \n",
				errno, strerror(errno));
			return -1;
		}

		for (i = 0; i < cleandns->listen_num; i++) {
			listen_t* listen = cleandns->listens + i;

			if (FD_ISSET(listen->sock, &errorset)) {
				loge("do_loop(): listen_sock error\n");
				return -1;
			}

			if (FD_ISSET(listen->sock, &readset))
				handle_listen_sock(cleandns, listen);
		}

		for (i = 0; i < cleandns->dns_server_num; i++) {
			dns_server_t* dnsserver = cleandns->dns_servers + i;

			if (!dnsserver->udpsock) continue;

			if (FD_ISSET(dnsserver->udpsock, &errorset)) {
				loge("do_loop(): dnsserver.udpsock error\n");
				return -1;
			}

			if (FD_ISSET(dnsserver->udpsock, &readset))
				handle_remote_udprecv(cleandns, dnsserver,
					dnsserver->udpsock, NULL);
		}

		if (cleandns->proxy_server.udpsock) {

			if (FD_ISSET(cleandns->proxy_server.udpsock, &errorset)) {
				loge("do_loop(): proxy_server.udpsock error\n");
				return -1;
			}

			if (FD_ISSET(cleandns->proxy_server.udpsock, &readset))
				handle_remote_udprecv(cleandns, NULL,
					cleandns->proxy_server.udpsock, &cleandns->proxy_server);
		}

		item = req_list.nodes->items;
		while (item) {
			n = item->node;
			req = n->info;
			item = item->next;

			if (req) {
				conn_t* conn;
				for (i = 0; i < req->conn_num; i++) {
					conn = req->conns + i;
					if (conn->sock <= 0)
						continue;

					if (FD_ISSET(conn->sock, &errorset)) {
						loge("do_loop(): socket error\n");
						free_conn(conn);
						continue;
					}

					if (FD_ISSET(conn->sock, &writeset)) {
						if (conn->status == CONN_CONNECTING) {
							dns_server_t* dns_server = &cleandns->dns_servers[conn->dns_server_index];
							conn->status = CONN_CONNECTED;
							logi("connected to '%s'%s (TCP)\n",
								get_dnsservername(dns_server),
								conn->by_proxy ? " by proxy" : "");
						}
						if (tcp_send(cleandns, conn) == -1) {
							dns_server_t* dns_server = &cleandns->dns_servers[conn->dns_server_index];
							loge("do_loop(): cannot send data to '%s' (TCP)\n",
								get_dnsservername(dns_server));
							free_conn(conn);
						}
					}

					if (FD_ISSET(conn->sock, &readset)) {
						handle_remote_tcprecv(cleandns, req, conn, i);
					}
				}

				if (req->ns_msg_num >= req->wait_num) {
					queue_remove_bynode(cleandns, n);
					response_best_nsmsg(cleandns, req);
				}
				else {
					time_t now = time(NULL);
					if (req->expire <= now) {
						logw("timeout: questions=%s\n", req->questions);
						queue_remove_bynode(cleandns, n);
						response_best_nsmsg(cleandns, req);
					}
				}

			}
			else {
				queue_remove_bynode(cleandns, n);
			}
		}

		rbnode_list_destroy(req_list.nodes);
	}

	return 0;
}

static void free_conn(conn_t* conn)
{
	if (conn) {
		if (conn->sock > 0) {
			close(conn->sock);
			conn->sock = 0;
		}
		if (conn->proxy_state) {
			if (conn->proxy_state->sendbuf) {
				free(conn->proxy_state->sendbuf);
				conn->proxy_state->sendbuf = NULL;
				conn->proxy_state->sendbuf_size = 0;
			}
			free(conn->proxy_state);
			conn->proxy_state = NULL;
		}
		if (conn->sendbuf) {
			free(conn->sendbuf);
			conn->sendbuf = NULL;
			conn->sendbuf_size = 0;
		}
		if (conn->recvbuf) {
			free(conn->recvbuf);
			conn->recvbuf = NULL;
			conn->recvbuf_size = 0;
		}
	}
}

static req_t *new_req()
{
    req_t *req;
	req = malloc(sizeof(req_t));
    if (req == NULL)
        return NULL;
    memset(req, 0, sizeof(req_t));
    req->addrlen = sizeof(req->addr);
    return req;
}

static void free_req(req_t *req)
{
    if (req) {
		int i;
		conn_t* conn;
		for (i = 0; i < req->conn_num; i++) {
			conn = req->conns + i;
			free_conn(conn);
		}
		for (i = 0; i < req->ns_msg_num; i++) {
			ns_msg_free(req->ns_msg + i);
		}
		free(req->questions);
		free(req);
    }
}

static int queue_add(cleandns_ctx *cleandns, req_t *req)
{
    uint16_t newid;
    rbnode_t *n;

    do {
        newid = (uint16_t)(rand() % 0x7FFF);
		fix_reqid(&newid, cleandns->dns_server_num);
    } while(newid == 0 || rbtree_lookup(&cleandns->queue, (int)newid));

    req->id = newid;

    n = rbtree_insert(&cleandns->queue, newid, req);
    if (n == NULL)
        return -1;

    return 0;
}

static void queue_remove(cleandns_ctx *cleandns, req_t *req)
{
    rbtree_delete_bykey(&cleandns->queue, req->id);
}

static void queue_remove_bynode(cleandns_ctx *cleandns, rbnode_t *n)
{
    rbtree_delete(&cleandns->queue, n);
}

static int get_questions(stream_t *s, ns_msg_t *msg)
{
	int i, r, len = 0;
	for (i = 0; i < msg->qdcount; i++) {
		r = stream_writef(s, i > 0 ? ", %s" : "%s", msg->qrs[i].qname);
		if (r < 0)
			return -1;
		len += r;
	}
	return len;
}

static int get_answers(stream_t *s, ns_msg_t *msg)
{
	int i, rrcount, r, len = 0;
	ns_rr_t *rr;
	for (i = 0, rrcount = ns_rrcount(msg); i < rrcount; i++) {
		rr = msg->rrs + i;
		if (rr->type == NS_QTYPE_A) {
			char ipname[INET6_ADDRSTRLEN];
			struct in_addr *addr = (struct in_addr *)rr->rdata;
			inet_ntop(AF_INET, addr, ipname, INET6_ADDRSTRLEN);
			r = stream_writef(s, len > 0 ? ", %s" : "%s", ipname);
			if (r < 0)
				return -1;
			len += r;
		}
		else if (rr->type == NS_QTYPE_AAAA) {
			struct in6_addr*addr = (struct in6_addr*)rr->rdata;
			static char ipname[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, addr, ipname, INET6_ADDRSTRLEN);
			r = stream_writef(s, len > 0 ? ", %s" : "%s", ipname);
			if (r < 0)
				return -1;
			len += r;
		}
		else if (rr->type == NS_QTYPE_PTR) {
			r = stream_writef(s, len > 0 ? ", prt: %s" : "prt: %s", rr->rdata);
			if (r < 0)
				return -1;
			len += r;
		}
		else if (rr->type == NS_QTYPE_CNAME) {
			r = stream_writef(s, len > 0 ? ", cname: %s" : "cname: %s", rr->rdata);
			if (r < 0)
				return -1;
			len += r;
		}
		else if (rr->type == NS_QTYPE_SOA) {
			ns_soa_t *soa = rr->rdata;
			r = stream_writef(s, len > 0 ? ", ns1: %s, ns2: %s" : "ns1: %s, ns2: %s", soa->mname, soa->rname);
			if (r < 0)
				return -1;
			len += r;
		}
		else {
			/* do nothing */
		}
	}
	return len;
}

static void print_request(char *questions, struct sockaddr *from_addr)
{
	logi("request %s from %s\n", questions,
		from_addr ? get_addrname(from_addr) : "");
}

static void print_response(cleandns_ctx* cleandns, ns_msg_t *msg, struct sockaddr *from_addr)
{
	dns_server_t* dns_server = &cleandns->dns_servers[dns_index(msg->id, cleandns->dns_server_num)];
	stream_t rq = STREAM_INIT();
	stream_t rs = STREAM_INIT();
	get_questions(&rq, msg);
	get_answers(&rs, msg);
	logi("recv response %s from %s (%s)%s: %s\n",
		rq.array,
		from_addr ? get_addrname(from_addr) : "",
		dns_server->is_foreign ? "foreign" : "china",
		dns_server->addr.protocol == IPPROTO_TCP ? "(TCP)" : "",
		rs.array);
	stream_free(&rq);
	stream_free(&rs);
}

static int send_nsmsg(cleandns_ctx *cleandns, ns_msg_t *msg,
	sock_t sock, struct sockaddr *to, socklen_t tolen,
	req_t *req)
{
	stream_t s = STREAM_INIT();
	int len;

	if (loglevel >= LOG_INFO) {
		if (msg->ancount > 0) {
			stream_t questions = STREAM_INIT();
			stream_t answers = STREAM_INIT();
			get_questions(&questions, msg);
			get_answers(&answers, msg);
			logi("response to '%s': questions=%s, answers=%s\n",
				get_addrname(to),
				questions.array,
				answers.array);
			stream_free(&questions);
			stream_free(&answers);
		}
	}

	if ((len = ns_serialize(&s, msg, 0)) <= 0) {
		loge("send_nsmsg: Can't serialize the 'msg'\n");
		stream_free(&s);
		return -1;
	}

	logd("send data to '%s':\n", get_addrname(to));
	bprint(s.array, s.size);

	if (sendto(sock, s.array, s.size, 0, to, tolen) == -1) {
		loge("send_nsmsg(): cannot send data to '%s': sendto() error: errno=%d, %s\n",
			get_addrname(to), errno, strerror(errno));
		stream_free(&s);
		return -1;
	}

	stream_free(&s);

	return 0;
}

static int send_nsmsg_to_dns_server(cleandns_ctx *cleandns, ns_msg_t *msg,
	req_t *req, subnet_t *subnet,
	int dns_server_index, dns_server_t *dns_server)
{
	stream_t s = STREAM_INIT();
	int len;
	int is_tcp = dns_server->addr.protocol == IPPROTO_TCP;
	struct sockaddr *to = dns_server->addr.addrinfo->ai_addr;
	socklen_t tolen = (socklen_t)dns_server->addr.addrinfo->ai_addrlen;
	int compression = dns_server->is_foreign;
	sock_t sock = dns_server->udpsock;

	if (subnet) {
        ns_rr_t *rr;
		rr = ns_find_opt_rr(msg);
        if (rr == NULL) {
            rr = ns_add_optrr(msg);
            if (rr == NULL) {
                loge("send_nsmsg_to_dns_server: Can't add option record to ns_msg_t\n");
                return -1;
            }
        }

		rr->cls = NS_PAYLOAD_SIZE; /* reset edns payload size */

        if (ns_optrr_set_ecs(rr, (struct sockaddr *)&subnet->addr, subnet->mask, 0) != 0) {
            loge("send_nsmsg_to_dns_server: Can't add ecs option\n");
            return -1;
        }
	}

	if (loglevel >= LOG_INFO) {
		if (subnet) {
			logi("building msg with '%s' - %s://%s\n",
				subnet->name,
				is_tcp ? "tcp" : "udp",
				get_addrname(to));
		}
		else {
			logi("building msg - %s://%s\n",
				is_tcp ? "tcp" : "udp",
				get_addrname(to));
		}
	}

	if (is_tcp) {
		stream_writei16(&s, 0);
	}
	else if (dns_server->is_foreign && cleandns->proxy_server.addr) {
		stream_writei8(&s, 0);
		stream_writei8(&s, 0);
		stream_writei8(&s, 0);

		if (to->sa_family == AF_INET) {
			struct sockaddr_in *to4 = (struct sockaddr_in*)to;
			stream_writei8(&s, 1); /* IPv4 */
			stream_write(&s, (char*)(&to4->sin_addr), 4);
			stream_writei8(&s, (to4->sin_port & 0xff));
			stream_writei8(&s, ((to4->sin_port >> 8) & 0xff));
		}
		else { 
			struct sockaddr_in6* to6 = (struct sockaddr_in6*)to;
			stream_writei8(&s, 4); /* IPv6 */
			stream_write(&s, (char*)(&to6->sin6_addr), 16);
			stream_writei8(&s, (to6->sin6_port & 0xff));
			stream_writei8(&s, ((to6->sin6_port >> 8) & 0xff));
		}

		to = cleandns->proxy_server.addr->ai_addr;
		tolen = (socklen_t)cleandns->proxy_server.addr->ai_addrlen;
		sock = cleandns->proxy_server.udpsock;
	}

	if ((len = ns_serialize(&s, msg, compression)) <= 0) {
		loge("send_nsmsg_to_dns_server: Can't serialize the 'msg'\n");
		stream_free(&s);
		return -1;
	}

	if (is_tcp) {
		stream_seti16(&s, 0, len);
	}

	if (loglevel >= LOG_DEBUG) {
		bprint(s.array, s.size);
	}

	if (is_tcp) {
		if (req->conn_num >= MAX_NS_MSG) {
			loge("send_nsmsg_to_dns_server: too many connections\n");
			stream_free(&s);
			return -1;
		}
		conn_t* conn = &req->conns[req->conn_num++];
		memset(conn, 0, sizeof(conn_t));
		conn->status = CONN_CONNECTING;
		conn->dns_server_index = dns_server_index;
		conn->sendbuf = s.array;
		conn->sendbuf_size = s.size;
		memset(&s, 0, sizeof(stream_t));

		if (connect_server(cleandns, conn, dns_server) != 0) {
			loge("send_nsmsg_to_dns_server: cannot connect to '%s'\n", get_dnsservername(dns_server));
			free_conn(conn);
			return -1;
		}
		else if (conn->status == CONN_CONNECTED) {
			if (tcp_send(cleandns, conn) == -1) {
				loge("send_nsmsg_to_dns_server: cannot send data to '%s' (TCP)\n", get_dnsservername(dns_server));
				free_conn(conn);
				return -1;
			}
		}
		else {
			logi("connecting '%s'%s ... (TCP)\n",
				get_dnsservername(dns_server),
				conn->by_proxy ? " by proxy" : "");
		}
	}
	else {
		logi("send msg (%d bytes) to '%s'%s\n",
			s.size,
			get_dnsservername(dns_server),
			(dns_server->is_foreign&& cleandns->proxy_server.addr) ? " by proxy" : "");
		if (sendto(sock, s.array, s.size, 0, to, tolen) == -1) {
			loge("send_nsmsg_to_dns_server(): cannot send data to '%s': sendto() error: errno=%d, %s\n",
				get_addrname(to), errno, strerror(errno));
			stream_free(&s);
			return -1;
		}
	}

	stream_free(&s);

	return 0;
}

static int handle_listen_sock_recv_nsmsg(cleandns_ctx *cleandns, ns_msg_t *msg, req_t *req)
{
	int i, r;
	dns_server_t* dns_server;
	int compression;
	subnet_t *subnets[2];
	int subnet_num;
	sock_t sock;
	struct sockaddr *to;
	socklen_t tolen;

	logd("request msg:\n");
	ns_print(msg);

	for (i = 0; i < cleandns->dns_server_num; i++) {

		dns_server = cleandns->dns_servers + i;
		compression = dns_server->is_foreign;
		sock = dns_server->udpsock;
		to = dns_server->addr.addrinfo->ai_addr;
		tolen = (socklen_t)dns_server->addr.addrinfo->ai_addrlen;

		if (dns_server->is_foreign) {
			msg->id = (uint16_t)(req->id + cleandns->dns_server_num + i);
		}
		else {
			msg->id = (uint16_t)(req->id + i);
		}

		subnet_num = 0;

		if (msg->qrs && msg->qrs->qtype == NS_QTYPE_AAAA) {
			if (cleandns->china_net6.is_set)
				subnets[subnet_num++] = &cleandns->china_net6;
			if (cleandns->foreign_net6.is_set)
				subnets[subnet_num++] = &cleandns->foreign_net6;
		}
		else if (msg->qrs && msg->qrs->qtype == NS_QTYPE_A) {
			if (cleandns->china_net.is_set)
				subnets[subnet_num++] = &cleandns->china_net;
			if (cleandns->foreign_net.is_set)
				subnets[subnet_num++] = &cleandns->foreign_net;
		}

		if (subnet_num == 0) {
			r = send_nsmsg_to_dns_server(cleandns, msg, req, NULL, i, dns_server);
			if (r != 0) {
				loge("handle_listen_sock_recv_nsmsg: failed to send 'msg'.\n");
			}
			else {
				req->wait_num++;
			}
		}
		else {
			int j;
			for (j = 0; j < subnet_num; j++) {
				r = send_nsmsg_to_dns_server(cleandns, msg, req, subnets[j], i, dns_server);
				if (r != 0) {
					loge("handle_listen_sock_recv_nsmsg: failed to send 'msg'.\n");
				}
				else {
					req->wait_num++;
				}
			}
		}

	}

	if (req->wait_num == 0) {
		loge("handle_listen_sock_recv_nsmsg: no 'msg' send to dns server.\n");
		return -1;
	}

	return 0;
}

static int handle_listen_sock_recv(cleandns_ctx *cleandns,
        req_t *req, int len)
{
    ns_msg_t msg;
	int rc = -1;

	if (init_ns_msg(&msg) != 0) {
		loge("handle_listen_sock_recv: init_ns_msg()\n");
		return -1;
	}
	
	if (ns_parse(&msg, (uint8_t *)cleandns->buf, len) == 0) {
		stream_t questions = STREAM_INIT();

		get_questions(&questions, &msg);
		req->questions = questions.array;

		if (loglevel >= LOG_INFO) {
			print_request(req->questions, (struct sockaddr *)&req->addr);
		}

		req->old_id = msg.id;
        req->edns = (ns_find_ecs(&msg, NULL) != NULL);

		if (handle_listen_sock_recv_nsmsg(cleandns, &msg, req) != 0) {
			loge("handle_listen_sock_recv: failed to handle 'msg'.\n");
		}
		else {
			rc = 0;
		}

	}
	else {
		loge("handle_listen_sock_recv: Can't parse package\n");
	}

	ns_msg_free(&msg);

	return rc;
}

static int handle_listen_sock(cleandns_ctx *cleandns, listen_t *listen)
{
	int len;
    req_t *req;

    req = new_req();
    if (req == NULL) {
        loge("handle_listen_sock: new_req()\n");
        return -1;
    }

	req->listen = listen;
	req->expire = time(NULL) + cleandns->timeout;

    if (queue_add(cleandns, req) != 0) {
        loge("handle_listen_sock_recv: Can't add 'req' to queue\n");
        free_req(req);
        return -1;
    }

    len = recvfrom(listen->sock, cleandns->buf, NS_PAYLOAD_SIZE, 0,
            (struct sockaddr *)(&req->addr), &req->addrlen);
    if (len > 0) {

		logd("request data:\n");
		bprint(cleandns->buf, len);

		if (handle_listen_sock_recv(cleandns, req, len) != 0) {
           loge("handle_listen_sock: handle_listen_sock_recv()\n");
           queue_remove(cleandns, req);
           free_req(req);
           return -1;
        }
		else {
			return 0;
		}
    }
    else {
		loge("handle_listen_sock() - recvfrom() error: errno=%d, %s\n", errno, strerror(errno));
		queue_remove(cleandns, req);
        free_req(req);
        return -1;
    }
}

static int check_rr(cleandns_ctx *cleandns, ns_rr_t *rr)
{
	if (rr->type == NS_QTYPE_A) {
		struct in_addr *addr = (struct in_addr *)rr->rdata;
		if (test_ip_in_list4(addr, &cleandns->chnroute_list)) {
			return FLG_A_CHN;
		}
		else {
			return FLG_A;
		}
	}
	else if (rr->type == NS_QTYPE_AAAA) {
		struct in6_addr *addr = (struct in6_addr*)rr->rdata;
		if (test_ip_in_list6(addr, &cleandns->chnroute_list)) {
			return FLG_AAAA_CHN;
		}
		else {
			return FLG_AAAA;
		}
	}
	else if (rr->type == NS_QTYPE_PTR) {
		return FLG_PTR;
	}
	else if (rr->type == NS_QTYPE_OPT) {
		return FLG_OPT;
	}
	return FLG_NONE;
}

static int check_ns_msg_normal(cleandns_ctx* cleandns, ns_msg_t* msg)
{
	int i, rrcount, flags = 0;
	ns_rr_t* rr;

	rrcount = msg->ancount + msg->nscount;
	for (i = 0; i < rrcount; i++) {
		rr = msg->rrs + i;
		flags |= check_rr(cleandns, rr);
	}

	rrcount = ns_rrcount(msg);
	for (; i < rrcount; i++) {
		rr = msg->rrs + i;
		flags |= check_rr(cleandns, rr);
	}

	return flags;
}

static int check_ns_msg_pollute(cleandns_ctx* cleandns, ns_msg_t* msg)
{
	int i, rrcount, flags = 0;
	ns_rr_t* rr;

	if (!cleandns->lazy) {
		int dns_idx;
		int is_foreign_dns;
		dns_server_t* dns_server;

		dns_idx = dns_index(msg->id, cleandns->dns_server_num);
		dns_server = cleandns->dns_servers + dns_idx;
		is_foreign_dns = dns_server->is_foreign;

		if (msg->qdcount == 0)
			return FLG_POLLUTE;

		if (msg->ancount == 0)
			return FLG_POLLUTE;

		/*if it's come from foreign dns server, it should be have esc.*/
		if (is_foreign_dns) {
			if (msg->ancount < 2 && msg->arcount == 0)
				return FLG_POLLUTE;
		}
	}

	rrcount = msg->ancount + msg->nscount;
	for (i = 0; i < rrcount; i++) {
		rr = msg->rrs + i;
		flags |= check_rr(cleandns, rr);

		/* edns should be in additional records section */
		if (!cleandns->lazy && (flags & FLG_OPT))
			return FLG_POLLUTE;
	}

	rrcount = ns_rrcount(msg);
	for (; i < rrcount; i++) {
		rr = msg->rrs + i;
		flags |= check_rr(cleandns, rr);
	}

	return flags;
}

static int check_ns_msg(cleandns_ctx* cleandns, ns_msg_t* msg)
{
	int flags = 0;
	int by_proxy;
	int dns_idx;
	int is_foreign_dns;
	int is_tcp;
	dns_server_t* dns_server;

	dns_idx = dns_index(msg->id, cleandns->dns_server_num);
	dns_server = cleandns->dns_servers + dns_idx;
	is_foreign_dns = dns_server->is_foreign;
	by_proxy = is_foreign_dns && cleandns->proxy_server.addr;
	is_tcp = dns_server->addr.protocol == IPPROTO_TCP;
	
	if (by_proxy || is_tcp || !is_foreign_dns) {
		return check_ns_msg_normal(cleandns, msg);
	}
	else {
		return check_ns_msg_pollute(cleandns, msg);
	}
}

static int is_subnet_match(void* a, void* b, int max_len, int prefix)
{
	int addrlen;
	uint8_t mask = 0xff;
	uint8_t copiedA[16], copiedB[16];

	memcpy(copiedA, a, max_len);
	memcpy(copiedB, b, max_len);

	addrlen = prefix / 8;
	if (prefix % 8)
		addrlen++;

	if (prefix % 8) {
		mask <<= (8 - (prefix % 8));
		copiedA[addrlen - 1] &= mask;
		copiedB[addrlen - 1] &= mask;
	}

	return memcmp(copiedA, copiedB, addrlen) == 0;
}

static int is_foreign_ecs_subnet(cleandns_ctx* cleandns, ns_msg_t* msg)
{
	ns_ecs_t ecs;

	if (msg->qrs && msg->qrs->qtype == NS_QTYPE_A) {
		if (!cleandns->foreign_net.is_set)
			return FALSE;

		/* No ECS. May be polluted or the server do not support EDNS */
		if (!ns_try_read_ecs(msg, &ecs))
			return FALSE;

		if (ecs.family == ADDR_FAMILY_NUM_IP) {
			struct in_addr* ip = &((struct sockaddr_in*)&cleandns->foreign_net.addr)->sin_addr;
			return is_subnet_match(ip, (struct in_addr*)ecs.subnet, 4, cleandns->foreign_net.mask);
		}
		else {
			/* Polluted */
		}

		return FALSE;
	}
	else if (msg->qrs && msg->qrs->qtype == NS_QTYPE_AAAA) {
		if (!cleandns->foreign_net6.is_set)
			return FALSE;

		/* No ECS. May be polluted or the server do not support EDNS */
		if (!ns_try_read_ecs(msg, &ecs))
			return FALSE;

		if (ecs.family == ADDR_FAMILY_NUM_IP6) {
			struct in6_addr* ip = &((struct sockaddr_in6*)&cleandns->foreign_net6.addr)->sin6_addr;
			return is_subnet_match(ip, (struct in6_addr*)ecs.subnet, 16, cleandns->foreign_net6.mask);
		}
		else {
			/* Polluted */
		}

		return FALSE;
	}
	 

	return FALSE;
}

static int response_best_nsmsg(cleandns_ctx* cleandns, req_t* req)
{
	ns_msg_t* best = NULL;
	dns_server_t* dns_server;

	if (req->ns_msg_num == 0) {
		loge("%s: resolve failed.\n", req->questions);
		return -1;
	}
	else {

		int score[MAX_NS_MSG] = { 0 };
		int i, flags, best_index = 0;
		ns_msg_t* msg;

		for (i = 0; i < req->ns_msg_num; i++) {
			msg = req->ns_msg + i;
			dns_server = cleandns->dns_servers + dns_index(msg->id, cleandns->dns_server_num);

			flags = check_ns_msg(cleandns, msg);
			if (flags & FLG_POLLUTE) {
				if (loglevel >= LOG_INFO) {
					logi("response_best_nsmsg: polluted msg (#%d)\n", i);
				}
				score[i] = -1;
			}
			else {
				/* chose a best msg */
				int haveip;
				haveip = (flags & (FLG_A | FLG_AAAA | FLG_A_CHN | FLG_AAAA_CHN));
				if (haveip) {
					int chnip, chnsubnet, chndns;

					chnip = (flags & (FLG_A_CHN | FLG_AAAA_CHN)); /* have chinese ip(s) in result */
					chnsubnet = !is_foreign_ecs_subnet(cleandns, msg); /* edns-client-subnet with chinese ip */
					chndns = test_addr_in_list(dns_server->addr.addrinfo->ai_addr, &cleandns->chnroute_list); /* from china dns server */

					score[i] += 1;

					if (chnip) {
						if (chnsubnet)
							score[i] += 10;
						else
							score[i] += 5;
						if (chndns)
							score[i] += 20;
						else
							score[i] += 10;
					}
					else {
						if (chnsubnet)
							score[i] += 2;
						else
							score[i] += 4;
						if (chndns)
							score[i] += 5;
						else
							score[i] += 10;
					}

				}
				else {
					score[i] = 0;
				}
			}
		}

		for (i = 0; i < req->ns_msg_num; i++) {
			if (score[best_index] < score[i]) {
				best_index = i;
			}
		}
		best = req->ns_msg + best_index;
		if (loglevel >= LOG_INFO) {
			dns_server = cleandns->dns_servers + dns_index(best->id, cleandns->dns_server_num);
			logi("best answers come from '%s'\n",
				get_dnsservername(dns_server));
		}
	}

	if (best) {
		int rc = -1;
		
		if (loglevel >= LOG_INFO) {
			ns_rr_t* rr;
			char *dns_name;

			rr = ns_find_opt_rr(best);

			if (rr == NULL) {
				rr = ns_add_optrr(best);
				if (rr == NULL) {
					loge("response_best_nsmsg: Can't add option record to ns_msg_t\n");
					return -1;
				}
			}

			dns_server = cleandns->dns_servers + dns_index(best->id, cleandns->dns_server_num);

			dns_name = get_dnsservername(dns_server);

			rr->cls = NS_PAYLOAD_SIZE; /* reset edns payload size */

			if (ns_optrr_set_opt(rr, NS_OPTCODE_SVR, (uint16_t)(strlen(dns_name) + 1), dns_name) == NULL) {
				loge("response_best_nsmsg: Can't add dns name\n");
				return -1;
			}
		}
		

		best->id = req->old_id;

		if (send_nsmsg(cleandns, best,
			req->listen->sock,
			(struct sockaddr*)(&req->addr),
			req->addrlen, req) != 0) {
			loge("response_best_nsmsg: failed to send answers to '%s'\n",
				get_addrname((struct sockaddr*)(&req->addr)));
		}
		else {
			if (loglevel >= LOG_INFO) {
				logi("send answers to '%s'\n",
					get_addrname((struct sockaddr*)(&req->addr)));
			}
			rc = 0;
		}

		free_req(req);

		return rc;
	}
	else {
		loge("%s: no answer\n", req->questions);

		free_req(req);

		return -1;
	}

}

static int handle_remote_sock_recv_nsmsg(cleandns_ctx *cleandns, ns_msg_t *msg)
{
	rbnode_t *reqnode;
	uint16_t reqid;
	req_t *req;
	int flags;

	logd("response msg:\n");
	ns_print(msg);

	reqid = msg->id;
	fix_reqid(&reqid, cleandns->dns_server_num);

	reqnode = rbtree_lookup(&cleandns->queue, reqid);
	if (reqnode == NULL) {
		if (loglevel >= LOG_INFO) {
			logi("handle_remote_sock_recv_nsmsg: skip\n");
		}
		return 0;
	}

	req = reqnode->info;

	flags = check_ns_msg(cleandns, msg);
	if (flags & FLG_POLLUTE) {
		if (loglevel >= LOG_INFO) {
			logi("handle_remote_sock_recv_nsmsg: drop polluted msg\n");
		}
		return 0;
	}

	if (req->ns_msg_num < MAX_NS_MSG) {
		/* save msg */
		memcpy(req->ns_msg + (req->ns_msg_num++), msg, sizeof(ns_msg_t));

		/* clear, so there do not free the copied files when 'ns_msg_free(msg)' */
		memset(msg, 0, sizeof(ns_msg_t));
	}

	return 0;
}

static int handle_remote_sock_recv(cleandns_ctx *cleandns, char *buf, int len, struct sockaddr *from_addr)
{
	ns_msg_t msg;
	int rc = -1;

	if (init_ns_msg(&msg) != 0) {
		loge("handle_remote_sock_recv: init_ns_msg()\n");
		return -1;
	}

	if (ns_parse(&msg, (uint8_t *)buf, len) == 0) {

		if (loglevel >= LOG_INFO) {
			print_response(cleandns, &msg, from_addr);
		}

		if (handle_remote_sock_recv_nsmsg(cleandns, &msg) == 0) {
			rc = 0;
		}
		else {
			loge("handle_remote_sock_recv: failed to handle 'msg'.\n");
		}
	}
	else {
		loge("handle_remote_sock_recv: Can't parse package\n");
	}

	ns_msg_free(&msg);

	return rc;

    
}

static int handle_remote_udprecv(cleandns_ctx* cleandns, dns_server_t* dnsserver,
	sock_t sock, proxy_server_t *proxyserver)
{
	struct sockaddr_storage from_addr;
	socklen_t from_addrlen = sizeof(struct sockaddr_storage);
	char* buf = cleandns->buf;
	int bufsize = sizeof(cleandns->buf);
	int len;

	memset(&from_addr, 0, sizeof(struct sockaddr_storage));

	len = recvfrom(sock, buf, bufsize, 0,
		(struct sockaddr*) & from_addr, &from_addrlen);

	if (len > 0) {

		if (len < 10) {
			loge("handle_remote_udprecv: invalid data\n");
			return -1;
		}

		logd("recv data:\n");
		bprint(buf, len);

		if (proxyserver) {
			if (buf[3] == 1) { /* IPv4 */
				struct sockaddr_in* src_addr = (struct sockaddr_in*) & from_addr;
				uint16_t src_port = 0;
				memcpy(&src_addr->sin_addr, buf + 4, 4);
				src_port = (buf[8] << 8) & 0xFF00;
				src_port |= buf[9];
				src_addr->sin_port = htons(src_port);
				src_addr->sin_family = AF_INET;
				buf += 10;
				len -= 10;
			}
			else if (buf[3] == 4) { /* IPv6 */
				struct sockaddr_in6* src_addr = (struct sockaddr_in6*) & from_addr;
				uint16_t src_port = 0;
				memcpy(&src_addr->sin6_addr, buf + 4, 16);
				src_port = (buf[20] << 8) & 0xFF00;
				src_port |= buf[21];
				src_addr->sin6_port = htons(src_port);
				src_addr->sin6_family = AF_INET6;
				buf += 22;
				len -= 22;
			}
			else {
				loge("handle_remote_udprecv: invalid atyp\n");
				return -1;
			}
		}

		if (handle_remote_sock_recv(cleandns, buf, len, (struct sockaddr*) & from_addr) != 0) {
			loge("handle_remote_udprecv: handle_remote_sock_recv() error\n");
			return -1;
		}
		else
			return 0;
	}
	else {
		loge("handle_remote_udprecv() - recvfrom() error: errno=%d, %s\n", errno, strerror(errno));
		return -1;
	}
}

static int handle_remote_tcprecv(cleandns_ctx* cleandns, req_t *req, conn_t *conn, int conn_index)
{
	dns_server_t* dns_server = &cleandns->dns_servers[conn->dns_server_index];
	struct sockaddr* dns_addr = dns_server->addr.addrinfo->ai_addr;
	int nread;

	if (!conn->recvbuf) {
		conn->recvbuf = (char *)malloc(NS_PAYLOAD_SIZE);
		if (!conn->recvbuf) {
			loge("tcp_recv(): alloc memory\n");
			free_conn(conn);
			return -1;
		}
	}

	nread = recv(conn->sock,
		conn->recvbuf + conn->recvbuf_size,
		NS_PAYLOAD_SIZE - conn->recvbuf_size, 0);

	if (nread > 0) {
		int partly_recv = 0;
		int msglen = 0;

		conn->recvbuf_size += nread;

		if (conn->by_proxy && conn->status != CONN_PROXY_CONNECTED) {
			proxy_state_t* proxy_state = conn->proxy_state;
			logd("recv %d bytes from proxy server\n", conn->recvbuf_size);
			bprint(conn->recvbuf, conn->recvbuf_size);
			switch (conn->status) {
			case CONN_PROXY_HANKSHAKE_1:
				if (conn->recvbuf_size == 2 && conn->recvbuf[0] == 0x5 && conn->recvbuf[1] == 0x0) {
					conn->recvbuf_size = 0;
					if (conn->sendbuf) {
						loge("tcp_recv() error: stack overflow \n");
						free_conn(conn);
						return -1;
					}

					conn->sendbuf = (char*)malloc(32);
					if (!conn->sendbuf) {
						loge("tcp_recv() error: alloca \n");
						free_conn(conn);
						return -1;
					}
					memset(conn->sendbuf, 0, 32);

					if (dns_addr->sa_family == AF_INET) {
						conn->sendbuf_size = 10;
						conn->sendbuf[0] = 0x5;
						conn->sendbuf[1] = 0x1;
						conn->sendbuf[3] = 0x1;
						memcpy(conn->sendbuf + 4, &((struct sockaddr_in*)dns_addr)->sin_addr, 4);
						*(conn->sendbuf + 8) = (((struct sockaddr_in*)dns_addr)->sin_port & 0xff);
						*(conn->sendbuf + 9) = ((((struct sockaddr_in*)dns_addr)->sin_port >> 8) & 0xff);
					}
					else if (dns_addr->sa_family == AF_INET6) {
						conn->sendbuf_size = 22;
						conn->sendbuf[0] = 0x5;
						conn->sendbuf[1] = 0x1;
						conn->sendbuf[3] = 0x4;
						memcpy(conn->sendbuf + 4, &((struct sockaddr_in6*)dns_addr)->sin6_addr, 16);
						*(conn->sendbuf + 20) = (((struct sockaddr_in6*)dns_addr)->sin6_port & 0xff);
						*(conn->sendbuf + 21) = ((((struct sockaddr_in6*)dns_addr)->sin6_port >> 8) & 0xff);
					}
					else {
						loge("tcp_recv() error: stack overflow \n");
						return -1;
					}
					
					conn->status = CONN_PROXY_HANKSHAKE_2;
					return 0;
				}
				else {
					loge("tcp_recv() error: reject by proxy server\n");
					free_conn(conn);
					return -1;
				}
				break;
			case CONN_PROXY_HANKSHAKE_2:
				if (conn->recvbuf_size == 10 && conn->recvbuf[0] == 0x5 && conn->recvbuf[3] == 0x1) {
					conn->status = CONN_PROXY_CONNECTED;
					conn->recvbuf_size = 0;
					if (conn->sendbuf) {
						loge("tcp_recv() error: stack overflow \n");
						return -1;
					}
					conn->sendbuf = proxy_state->sendbuf;
					conn->sendbuf_size = proxy_state->sendbuf_size;
					proxy_state->sendbuf = NULL;
					proxy_state->sendbuf_size = 0;
					return 0;
				}
				else {
					loge("tcp_recv() error: reject by proxy server\n");
					free_conn(conn);
					return -1;
				}
			default:
				loge("tcp_recv() error: invalid status '%d' \n", conn->status);
				free_conn(conn);
				return -1;
			}
		}
		else {
			logd("recv %d bytes from '%s' (TCP)\n", nread, get_addrname(dns_addr));
		}

		if (conn->recvbuf_size > 2) {
			stream_t s = {
				.array = conn->recvbuf,
				.size = conn->recvbuf_size,
				.pos = 0,
				.cap = NS_PAYLOAD_SIZE
			};
			msglen = stream_readi16(&s);
			if (msglen + 2 > NS_PAYLOAD_SIZE) {
				loge("tcp_recv(): too big payload size\n");
				free_conn(conn);
				return -1;
			}
			else if (msglen + 2 == conn->recvbuf_size) {

				/* recived all data, close the socket */
				close(conn->sock);
				conn->sock = 0;

				logd("response data (TCP):\n");
				bprint(conn->recvbuf + 2, msglen);

				if (handle_remote_sock_recv(cleandns, conn->recvbuf + 2, msglen, dns_server->addr.addrinfo->ai_addr) != 0) {
					loge("tcp_recv(): handle_remote_sock_recv() error\n");
					return -1;
				}
				else {
					return 0;
				}
			}
			else if (msglen + 2 > conn->recvbuf_size) {
				loge("tcp_recv(): invalid payload\n");
				free_conn(conn);
				return -1;
			}
			else {
				partly_recv = 1;
			}
		}
		else {
			partly_recv = 1;
		}

		if (partly_recv) {
			if (msglen > 0)
			{
				logd("partly recv %d bytes from '%s', expect %d\n",
					conn->recvbuf_size, get_addrname(dns_addr), msglen + 2);
			}
			else
			{
				logd("partly recv %d bytes from '%s'\n",
					conn->recvbuf_size, get_addrname(dns_addr));
			}
		}
		return 0;
	}
	else if (nread == 0) {
		loge("tcp_recv: connection closed by server '%s'\n", get_addrname(dns_addr));
		free_conn(conn);
		return -1;
	}
	else {
		int err = errno;
		if (is_eagain(err)) {

			logd("tcp_recv() EAGAIN (TCP) '%s'\n", get_addrname(dns_addr));

			return 0;
		}
		else {
			loge("tcp_recv() - recv() error: %s, errno=%d, %s\n",
				get_addrname(dns_addr), err, strerror(err));
			free_conn(conn);
			return -1;
		}
	}
}

static int setnonblock(sock_t sock)
{
#ifdef WINDOWS
	int iResult;
	/* If iMode!=0, non-blocking mode is enabled.*/
	u_long iMode = 1;
	iResult = ioctlsocket(sock, FIONBIO, &iMode);
	if (iResult != NO_ERROR) {
		loge("ioctlsocket() failed with error: %ld. errno=%d, %s\n",
			iResult, errno, strerror(errno));
		return -1;
	}
#else
	int flags;
	flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1) {
		loge("fcntl() error: errno=%d, %s\n", errno, strerror(errno));
		return -1;
	}
	if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
		loge("fcntl() error: errno=%d, %s\n", errno, strerror(errno));
		return -1;
	}
#endif

	return 0;
}

static int setreuseaddr(sock_t sock)
{
	int opt = 1;

	if (setsockopt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &opt, sizeof(opt)) != 0) {
		loge("setsockopt() error: errno=%d, %s\n", errno, strerror(errno));
		return -1;
	}

	return 0;
}

static int setnodelay(sock_t sock)
{
	int opt = 1;

	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) != 0) {
		loge("setsockopt() error: errno=%d, %s\n", errno, strerror(errno));
		return -1;
	}

	return 0;
}

static int tcp_send(cleandns_ctx* cleandns, conn_t* conn)
{
	dns_server_t* dns_server = &cleandns->dns_servers[conn->dns_server_index];
	struct sockaddr* to_addr = dns_server->addr.addrinfo->ai_addr;
	int nsend;

	if (conn->by_proxy && conn->status != CONN_PROXY_CONNECTED) {
		proxy_state_t* proxy_state;
		to_addr = cleandns->proxy_server.addr->ai_addr;
		switch (conn->status) {
		case CONN_CONNECTED:
			proxy_state = (proxy_state_t*)malloc(sizeof(proxy_state_t));
			if (!proxy_state) {
				loge("tcp_send() error: alloca \n");
				return -1;
			}
			proxy_state->sendbuf = conn->sendbuf;
			proxy_state->sendbuf_size = conn->sendbuf_size;
			conn->proxy_state = proxy_state;
			conn->sendbuf = (char*)malloc(8);
			if (!conn->sendbuf) {
				loge("tcp_send() error: alloca \n");
				return -1;
			}
			memset(conn->sendbuf, 0, 8);
			conn->sendbuf_size = 3;
			conn->sendbuf[0] = 0x5;
			conn->sendbuf[1] = 0x1;
			conn->status = CONN_PROXY_HANKSHAKE_1;
			logd("send %d bytes to proxy server\n", conn->sendbuf_size);
			bprint(conn->sendbuf, conn->sendbuf_size);
			break;
		case CONN_PROXY_HANKSHAKE_1:
			break;
		case CONN_PROXY_HANKSHAKE_2:
			logd("send %d bytes to proxy server\n", conn->sendbuf_size);
			bprint(conn->sendbuf, conn->sendbuf_size);
			break;
		default:
			loge("tcp_send() error: invalid proxy status '%d' \n", conn->status);
			return -1;
		}
	}

	nsend = send(conn->sock, conn->sendbuf, conn->sendbuf_size, 0);
	if (nsend == -1) {
		int err = errno;
		if (!is_eagain(err)) {
			loge("tcp_send() - send() error: %s, errno=%d, %s \n",
				get_addrname(to_addr), err, strerror(err));
			return -1;
		}
		logd("send() EAGAIN (TCP) %s\n", get_addrname(to_addr));
		return 0;
	}
	else if (nsend < conn->sendbuf_size) {
		logd("partly send %d bytes to '%s' (TCP)(sock=%d)\n",
			nsend, get_addrname(to_addr), conn->sock);
		/* partly sent, move memory, wait for the next time to send */
		memmove(conn->sendbuf, conn->sendbuf + nsend, (size_t)conn->sendbuf_size - nsend);
		conn->sendbuf_size -= nsend;
		return 0;
	}
	else {
		logd("send %d bytes to '%s' (TCP)(sock=%d)\n",
			nsend, get_addrname(to_addr), conn->sock);
		free(conn->sendbuf);
		conn->sendbuf = NULL;
		conn->sendbuf_size = 0;
		return 0;
	}
}

static int connect_server(cleandns_ctx *cleandns, conn_t *conn, dns_server_t *server)
{
	sock_t sock;
	int rv;

	if (server->is_foreign && cleandns->proxy_server.addr) {
		proxy_server_t* proxy = &cleandns->proxy_server;

		sock = socket(proxy->addr->ai_family, SOCK_STREAM, IPPROTO_TCP);
		if (sock == -1) {
			loge("connect_server(): Can't create proxy socket to '%s'. socket() error: errno=%d, %s\n",
				get_dnsservername(server), errno, strerror(errno));
			return -1;
		}

		if (setnonblock(sock) != 0) {
			close(sock);
			return -1;
		}

		if (setnodelay(sock) != 0) {
			close(sock);
			return -1;
		}

		rv = connect(sock, proxy->addr->ai_addr, (int)proxy->addr->ai_addrlen);

		conn->by_proxy = 1;
	}
	else {
		sock = socket(server->addr.addrinfo->ai_family, SOCK_STREAM, IPPROTO_TCP);
		if (sock == -1) {
			loge("connect_server(): Can't create socket to '%s'\n", get_dnsservername(server));
			return -1;
		}

		if (setnonblock(sock) != 0) {
			close(sock);
			return -1;
		}

		if (setnodelay(sock) != 0) {
			close(sock);
			return -1;
		}

		rv = connect(sock, server->addr.addrinfo->ai_addr, (int)server->addr.addrinfo->ai_addrlen);
	}

	if (rv != 0) {
		int err = errno;
		if (is_eagain(err)) {
			conn->sock = sock;
			return 0;
		}
		loge("connect_server(): connect to '%s' error. connect() error: errno=%d, %s\n",
			get_dnsservername(server), err, strerror(err));
		close(sock);
		return -1;
	}

	conn->status = CONN_CONNECTED;
	conn->sock = sock;

	logi("connected to '%s'%s (TCP)\n",
		conn->by_proxy ? " by proxy" : "",
		get_dnsservername(server));

	return 0;
}

static int init_listen(cleandns_ctx *cleandns, listen_t *ctx)
{
	struct addrinfo* addrinfo;
	int is_tcp;
	sock_t sock;

	addrinfo = ctx->addr.addrinfo;
	is_tcp = ctx->addr.protocol == IPPROTO_TCP;

	sock = socket(
		addrinfo->ai_family,
		is_tcp ? SOCK_STREAM : SOCK_DGRAM,
		is_tcp ? IPPROTO_TCP : IPPROTO_UDP);

	if (!sock) {
		loge("init_listen() - socket() error: errno=%d, %s\n", errno, strerror(errno));
		return -1;
	}

	if (setreuseaddr(sock) != 0) {
		loge("init_listen() error: set sock reuse address failed\n");
		close(sock);
		return -1;
	}

	if (setnonblock(sock) != 0) {
		loge("init_listen(): set sock non-block failed\n");
		close(sock);
		return -1;
	}

#ifdef WINDOWS
	if (!is_tcp) {
		disable_udp_connreset(sock);
	}
#endif

	if (bind(sock, addrinfo->ai_addr, (int)addrinfo->ai_addrlen) != 0) {
		loge("Can't bind address %s. bind() error: errno=%d, %s\n",
			get_addrname(addrinfo->ai_addr), errno, strerror(errno));
		close(sock);
		return -1;
	}

	if (is_tcp) {

		if (listen(sock, LISTEN_BACKLOG) != 0) {
			loge("Can't listen on %s. listen() error: errno=%d, %s\n",
				get_addrname(addrinfo->ai_addr), errno, strerror(errno));
			close(sock);
			return -1;
		}
	}

	ctx->sock = sock;

	return 0;
}

static int init_listens(cleandns_ctx *cleandns)
{
	int i, num = cleandns->listen_num;
	listen_t *listen;

	for (i = 0; i < num; i++) {
		listen = cleandns->listens + i;
		if (listen->addr.protocol == IPPROTO_TCP) {
			loge("init_listens() error: listen on TCP port is not support\n");
			return -1;
		}
		if (init_listen(cleandns, listen) != 0) {
			loge("init_listens() error\n");
			return -1;
		}
	}

	return 0;
}

static int init_dnsservers(cleandns_ctx *cleandns)
{
	int i, num = cleandns->dns_server_num;
	dns_server_t* dnsserver;
	struct addrinfo* addrinfo;
	int is_tcp;
	sock_t sock;

	for (i = 0; i < num; i++) {
		dnsserver = cleandns->dns_servers + i;
		is_tcp = dnsserver->addr.protocol == IPPROTO_TCP;
		if (!test_addr_in_list(
			dnsserver->addr.addrinfo->ai_addr,
			&cleandns->chnroute_list)) {
			dnsserver->is_foreign = 1;
		}
		else {
			dnsserver->is_foreign = 0;
		}
		if (is_tcp) continue;
		addrinfo = dnsserver->addr.addrinfo;
		sock = socket(
			addrinfo->ai_family,
			SOCK_DGRAM,
			IPPROTO_UDP);

		if (!sock) {
			loge("init_dnsservers() - socket() error: errno=%d, %s\n",
				errno, strerror(errno));
			return -1;
		}

		if (setnonblock(sock) != 0) {
			loge("init_dnsservers(): set sock non-block failed\n");
			close(sock);
			return -1;
		}

#ifdef WINDOWS
		disable_udp_connreset(sock);
#endif
		dnsserver->udpsock = sock;
	}

	return 0;
}

static int init_proxy_udpsock(cleandns_ctx* cleandns)
{
	struct addrinfo* addrinfo;
	sock_t sock;

	addrinfo = cleandns->proxy_server.addr;
	sock = socket(
		addrinfo->ai_family,
		SOCK_DGRAM,
		IPPROTO_UDP);

	if (!sock) {
		loge("init_proxy_udpsock() - socket() error: errno=%d, %s\n",
			errno, strerror(errno));
		return -1;
	}

	if (setnonblock(sock) != 0) {
		loge("init_proxy_udpsock(): set sock non-block failed\n");
		close(sock);
		return -1;
	}

#ifdef WINDOWS
	disable_udp_connreset(sock);
#endif

	cleandns->proxy_server.udpsock = sock;

	return 0;
}

static int parse_url(char *s, char **protocol, char **host, char **port)
{
	char *p;
	int cnt = 0;

	p = strstr(s, "://");
	if (p) {
		*protocol = s;
		*p = '\0';
		s = p + 3;
	}
	else {
		*protocol = NULL;
	}

	/* ipv6 */
	if (*s == '[') {
		p = strrchr(s, ']');
		if (p) {
			*host = s + 1;
			*p = '\0';
			p++;
			if (*p == ':')
				*port = p + 1;
			else
				*port = NULL;
			return 0;
		}
		else {
			return -1;
		}
	}

	p = strrchr(s, ':');
	if (p) {
		*port = p + 1;
		*p = '\0';
	}
	else {
		*port = NULL;
	}

	*host = s;

	return 0;
}

static int is_ipv6(const char* ip)
{
	return !!strchr(ip, ':');
}

static int resolve_netaddr(
	char *s, netaddr_t *addr,
	const char* default_port)
{
	char* protocol, * ip, * port;
	struct addrinfo hints;
	int r;

	memset(addr, 0, sizeof(netaddr_t));

	parse_url(s, &protocol, &ip, &port);

	if (protocol) {
		if (strcmp(protocol, "tcp") == 0)
			addr->protocol = IPPROTO_TCP;
		else if (strcmp(protocol, "udp") == 0)
			addr->protocol = IPPROTO_UDP;
		else {
			loge("resolve_netaddr(): unknown protocol \"%s\"\n", protocol);
			return -1;
		}
	}
	else {
		addr->protocol = IPPROTO_UDP;
	}

	if (!port || strlen(port) == 0)
		port = (char*)default_port;

	if (!port || strlen(port) == 0)
		port = "53";

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = is_ipv6(ip) ? AF_INET6 : AF_INET;
	hints.ai_socktype =
		(addr->protocol == IPPROTO_TCP) ?
		SOCK_STREAM :
		SOCK_DGRAM;

	if ((r = getaddrinfo(ip, port, &hints, &addr->addrinfo)) != 0) {
		loge("resolve_netaddr() - getaddrinfo() error: %s %s:%s\n", gai_strerror(r), ip, port);
		return -1;
	}

	return 0;
}

static int resolve_proxy_server(cleandns_ctx* cleandns)
{
	struct addrinfo hints;
	char *s, *protocol, *ip, *port;
	int r;
	proxy_server_t *proxy_server = &cleandns->proxy_server;

	s = strdup(cleandns->proxy);

	parse_url(s, &protocol, &ip, &port);

	if (protocol && strcmp(protocol, "socks5") != 0) {
		loge("only support 'socks5' proxy: %s://%s:%s\n", protocol, ip, port);
		free(s);
		return -1;
	}

	proxy_server->protocol = strdup(protocol ? protocol : "socks5");

	if (!port || strlen(port) == 0)
		port = "1080";

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = is_ipv6(ip) ? AF_INET6 : AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if ((r = getaddrinfo(ip, port, &hints, &proxy_server->addr)) != 0) {
		loge("resolve_proxy_server() - getaddrinfo() error: %s %s:%s\n", gai_strerror(r), ip, port);
		free(s);
		return -1;
	}

	free(s);

	return 0;
}

static int resolve_netaddrs(
	const char *str,
	netaddr_t *addrs,
	int max_num,
	int element_size,
	const char *default_port)
{
	char *s, *p, *url;
	int i,j;
	netaddr_t *addr;

	s = strdup(str);

	for (i = 0, p = strtok(s, ",");
		p && *p && i < max_num;
		p = strtok(NULL, ",")) {

		addr = (netaddr_t*)(((char *)addrs) + (size_t)element_size * i);

		url = strdup(p);

		if (resolve_netaddr(url, addr, default_port)) {
			free(url);
			for (j = 0; j < i; j++) {
				addr = (netaddr_t*)(((char*)addrs) + (size_t)element_size * j);
				if (addr->addrinfo) {
					freeaddrinfo(addr->addrinfo);
					addr->addrinfo = NULL;
				}
			}
			loge("resolve_netaddrs(): resolve \"%s\" failed\n", p);
			return -1;
		}

		free(url);

		i++;
	}

	free(s);

	return i;
}

static int resolve_listens(cleandns_ctx* cleandns)
{
	cleandns->listen_num = resolve_netaddrs(
		cleandns->listen_addr,
		&cleandns->listens[0].addr,
		MAX_LISTEN,
		sizeof(listen_t),
		cleandns->listen_port);

	if (cleandns->listen_num == -1) {
		loge("resolve_listens(): resolve \"%s\" failed\n",
			cleandns->listen_addr);
		return -1;
	}

	if (cleandns->listen_num == 0) {
		loge("no listen\n");
		return -1;
	}

	return 0;
}

static int resolve_dns_server(cleandns_ctx *cleandns)
{
	cleandns->dns_server_num = resolve_netaddrs(
		cleandns->dns_server,
		&cleandns->dns_servers[0].addr,
		MAX_DNS_SERVER,
		sizeof(dns_server_t),
		"53");

	if (cleandns->dns_server_num == -1) {
		loge("resolve_dns_server(): resolve \"%s\" failed\n",
			cleandns->dns_server);
		return -1;
	}

	if (cleandns->dns_server_num == 0) {
		loge("no dns server\n");
		return -1;
	}
	
	return 0;
}

static int cmp_net_mask(const void *a, const void *b)
{
	uint32_t x, y;
	x = ((net_mask_t*)a)->net;
	y = ((net_mask_t*)b)->net;
	if (x < y) return -1;
	else if (x > y) return 1;
	else return 0;
}

static int cmp_net_mask6(const void *a, const void *b)
{
	const net_mask6_t *x = a;
	const net_mask6_t *y = b;
	int i;
	for (i = 0; i < 4; i++) {
		if (x->net[i] < y->net[i]) return -1;
		else if (x->net[i] > y->net[i]) return 1;
	}
	return 0;
}

static int test_ip_in_list4(struct in_addr *ip, const net_list_t *netlist)
{
	int l = 0, r = netlist->entries - 1;
	int m, cmp;
	net_mask_t ip_net;
	net_mask_t* find;
	if (netlist->entries == 0)
		return 0;
	ip_net.net = ntohl(ip->s_addr);
	while (l != r) {
		m = (l + r) / 2;
		cmp = cmp_net_mask(&ip_net, &netlist->nets[m]);
		if (cmp < 0) {
            if (r != m)
                r = m;
            else
                break;
        }
        else {
            if (l != m)
                l = m;
            else
                break;
        }
    }
	find = &netlist->nets[l];
	if ((ip_net.net & find->mask) != find->net) {
		return 0;
	}
	return 1;
}

static int test_ip_in_list6(struct in6_addr*ip, const net_list_t *netlist)
{
	int l = 0, r = netlist->entries6 - 1;
	int m, cmp;
	int i;
	net_mask6_t ip_net;
	net_mask6_t *find;
	if (netlist->entries6 == 0)
		return 0;
	memcpy(ip_net.net, ip->s6_addr, 16);
	for (i = 0; i < 4; i++) {
		ip_net.net[i] = ntohl(ip_net.net[i]);
	}
	while (l != r) {
		m = (l + r) / 2;
		cmp = cmp_net_mask6(&ip_net, &netlist->nets6[m]);
		if (cmp < 0) {
			if (r != m)
				r = m;
			else
				break;
		}
		else {
			if (l != m)
				l = m;
			else
				break;
		}
	}
	find = &netlist->nets6[l];
	for (i = 0; i < 4; i++) {
		if ((ip_net.net[i] & find->mask[i]) != find->net[i]) {
			return 0;
		}
	}
	return 1;
}

static int test_addr_in_list(struct sockaddr* addr, const net_list_t* netlist)
{
	if (addr->sa_family == AF_INET) {
		return test_ip_in_list4(&((struct sockaddr_in*)addr)->sin_addr, netlist);
	}
	else if (addr->sa_family == AF_INET6) {
		return test_ip_in_list6(&((struct sockaddr_in6*)addr)->sin6_addr, netlist);
	}
	else {
		return 0;
	}
}

static char *get_addrname(struct sockaddr *addr)
{
    static char addrname[INET6_ADDRSTRLEN + 16];
    char sip[INET6_ADDRSTRLEN];
    if (addr->sa_family == AF_INET) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, sip, sizeof(sip));
        snprintf(addrname, sizeof(addrname), "%s:%d", sip,
                (int)(htons(addr_in->sin_port) & 0xFFFF));
    }
    else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
		inet_ntop(AF_INET6, &addr_in6->sin6_addr, sip, sizeof(sip));
        snprintf(addrname, sizeof(addrname), "[%s]:%d", sip,
                (int)(htons(addr_in6->sin6_port) & 0xFFFF));
	}
    else {
        addrname[0] = '\0';
    }
    return addrname;
}

static char *get_netaddrname(netaddr_t *addr)
{
	return get_addrname(addr->addrinfo->ai_addr);
}

static char* get_dnsservername(dns_server_t* dnsserver)
{
	return get_netaddrname(&dnsserver->addr);
}

static int parse_netmask(net_mask_t *netmask, char *line)
{
    char *sp_pos;
    struct in_addr ip;
	sp_pos = strchr(line, '/');
    if (sp_pos) {
        *sp_pos = 0;
		netmask->mask = UINT32_MAX ^ (((uint32_t)1 << (32 - atoi(sp_pos + 1))) - 1);
	}
    else {
        netmask->mask = UINT32_MAX;
    }
    if (inet_pton(AF_INET, line, &ip) == 0) {
        if (sp_pos) *sp_pos = '/';
        loge("invalid addr %s. parse_netmask() - inet_pton() error: errno=%d, %s\n",
			line, errno, strerror(errno));
        return -1;
    }
    netmask->net = ntohl(ip.s_addr);
    if (sp_pos) *sp_pos = '/';
	return 0;
}

static int parse_netmask6(net_mask6_t *netmask, char *line)
{
	char* sp_pos;
	struct in6_addr ip;
	int i,cidr;
	int quotient, remainder;
	sp_pos = strchr(line, '/');
	if (sp_pos) {
		*sp_pos = 0;
		cidr = atoi(sp_pos + 1);
	}
	else {
		cidr = 128;
	}
	if (inet_pton(AF_INET6, line, &ip) == 0) {
		if (sp_pos) *sp_pos = '/';
		loge("invalid addr %s. parse_netmask6() - inet_pton() error: errno=%d, %s\n",
			line, errno, strerror(errno));
		return -1;
	}
	memcpy(netmask->net, ip.s6_addr, 16);
	for (i = 0; i < 4; i++) {
		netmask->net[i] = ntohl(netmask->net[i]);
	}
	memset(netmask->mask, 0, sizeof(netmask->mask));
	quotient = cidr / 32;
	remainder = cidr % 32;
	for (i = 0; i < quotient; i++)
		netmask->mask[i] = UINT32_MAX;
	if (remainder > 0) {
		netmask->mask[quotient] = (((uint32_t)1 << (32 - remainder)) - 1) ^ UINT32_MAX;
	}
	if (sp_pos)* sp_pos = '/';
	return 0;
}

static void free_chnroute_list(dllist_t *list)
{
	dlitem_t *curr,*next;
	chnroute_item_t *item;

	dllist_foreach(list, curr, next, chnroute_item_t, item, entry) {
		free(item);
	}
}

static int parse_chnroute_file(chnroute_list_t *list, const char *filename)
{
	char buf[512];
	char *line;
	FILE *fp;
	int r, rownum = 0;
	chnroute_item_t *item;

	fp = fopen(filename, "rb");
	if (fp == NULL) {
		loge("Can't open chnroute: %s\n", filename);
		return -1;
	}

	if (fseek(fp, 0, SEEK_SET) != 0) {
		loge("fseek\n");
		fclose(fp);
		return -1;
	}

	while ((line = fgets(buf, sizeof(buf), fp)) != NULL) {
		char *sp_pos;

		rownum++;

		if ((*line) == '#') continue;

		sp_pos = strchr(line, '\r');
		if (sp_pos) *sp_pos = 0;

		sp_pos = strchr(line, '\n');
		if (sp_pos) *sp_pos = 0;

		if (!(*line)) continue;

		item = (chnroute_item_t*)malloc(sizeof(chnroute_item_t));
		if (!item) {
			loge("calloc\n");
			fclose(fp);
			return -1;
		}

		memset(item, 0, sizeof(chnroute_item_t));

		if (is_ipv6(line)) {
			r = parse_netmask6(&item->net6, line);
			item->is_ipv6 = 1;
		}
		else {
			r = parse_netmask(&item->net, line);
		}

		if (r != 0) {
            loge("invalid addr %s in %s:%d\n", line, filename, rownum);
			free(item);
			fclose(fp);
			return -1;
        }
		else {
			dllist_add(&list->items, &item->entry);
			if (item->is_ipv6)
				list->net6_num++;
			else
				list->net_num++;
		}
    }

	fclose(fp);

	return 0;
}

static int feedback_net_list(cleandns_ctx *cleandns, chnroute_list_t *list)
{
	net_list_t *netlist;

	netlist = &cleandns->chnroute_list;
	netlist->entries = 0;
	netlist->entries6 = 0;

	netlist->nets = calloc(list->net_num, sizeof(net_mask_t));
	if (netlist->nets == NULL) {
		loge("calloc\n");
		return -1;
	}

	netlist->nets6 = calloc(list->net6_num, sizeof(net_mask6_t));
	if (netlist->nets6 == NULL) {
		loge("calloc\n");
		free(netlist->nets);
		return -1;
	}

	{
		dlitem_t* curr, * next;
		chnroute_item_t* item;

		dllist_foreach(&list->items, curr, next, chnroute_item_t, item, entry) {
			if (item->is_ipv6) {
				netlist->nets6[netlist->entries6++] = item->net6;
			}
			else {
				netlist->nets[netlist->entries++] = item->net;
			}
		}
	}

	qsort(netlist->nets, netlist->entries, sizeof(net_mask_t), cmp_net_mask);

	qsort(netlist->nets6, netlist->entries6, sizeof(net_mask6_t), cmp_net_mask6);

	return 0;
}

static int parse_chnroute(cleandns_ctx* cleandns)
{
	char *s, *p;
	int r;
	chnroute_list_t list;

	memset(&list, 0, sizeof(chnroute_list_t));

	dllist_init(&list.items);

	s = strdup(cleandns->chnroute_file);

	for (p = strtok(s, ",");
		p && *p;
		p = strtok(NULL, ",")) {

		if (parse_chnroute_file(&list, p)) {
			free_chnroute_list(&list.items);
			return -1;
		}
	}

	free(s);

	r = feedback_net_list(cleandns, &list);

	free_chnroute_list(&list.items);

	return r;
}

static int parse_china_foreign_ip_single(subnet_t *subnet, const char *s)
{
	if (ns_ecs_parse_subnet((struct sockaddr*)(&subnet->addr),
		&subnet->mask, s) != 0) {
		loge("Invalid addr %s\n", s);
		return -1;
	}
	free(subnet->name);
	subnet->name = strdup(s);
	subnet->is_set = 1;
	return 0;
}

static int parse_china_foreign_ip(subnet_t *subnet4, subnet_t *subnet6, const char *str)
{
	char *s, *p;

	if (!str) return -1;
	if (!(*str)) return -1;

	s = strdup(str);

	for (p = strtok(s, ",");
		p && *p;
		p = strtok(NULL, ",")) {
		if (is_ipv6(p)) {
			if (parse_china_foreign_ip_single(subnet6, p))
				return -1;
		}
		else {
			if (parse_china_foreign_ip_single(subnet4, p))
				return -1;
		}
	}

	free(s);

	return 0;
}

static int parse_china_ip(cleandns_ctx* cleandns)
{
	return parse_china_foreign_ip(&cleandns->china_net, &cleandns->china_net6, cleandns->china_ip);
}

static int parse_foreign_ip(cleandns_ctx* cleandns)
{
	return parse_china_foreign_ip(&cleandns->foreign_net, &cleandns->foreign_net6, cleandns->foreign_ip);
}

/*left trim*/
static char* ltrim(char* s)
{
	char *p = s;
	while (p && (*p) && isspace(*p))
		p++;
	return p;
}

/*right trim*/
static char* rtrim(char* s)
{
	size_t len;
	char *p;

	len = strlen(s);
	p = s + len - 1;

	while (p >= s && isspace(*p)) (*(p--)) = '\0';

	return s;
}

static char* trim_quote(char* s)
{
	char *start, *end;
	size_t len;

	len = strlen(s);
	start = s;
	end = s + len - 1;

	while ((*start) && ((*start) == '\'' || (*start) == '"'))
		start++;

	while (end >= start && ((*end) == '\'' || (*end) == '"')) (*(end--)) = '\0';

	return start;
}

static void parse_option(char *ln, char **option, char **name, char **value)
{
	char *p = ln;

	*option = p;
	*name = NULL;
	*value = NULL;

	while (*p && !isspace(*p)) p++;

	if (!(*p))
		return;

	*p = '\0';

	p = ltrim(p + 1);

	*name = p;

	while (*p && !isspace(*p)) p++;

	if (!(*p))
		return;

	*p = '\0';

	p = ltrim(p + 1);

	*value = trim_quote(p);
}

static int read_config_file(cleandns_ctx* cleandns, const char *config_file, int force)
{
	FILE* pf;
	char line[2048], *ln;
	char *option, *name, *value;
	int len = 0, cnf_index = -1;

	pf = fopen(config_file, "r");
	if (!pf) {
		loge("failed to open %s\n", config_file);
		return -1;
	}

#define is_true_val(s) \
   (strcmp((s), "1") == 0 || \
    strcmp((s), "on") == 0 || \
	strcmp((s), "true") == 0 || \
	strcmp((s), "yes") == 0 || \
	strcmp((s), "enabled") == 0)

	while (!feof(pf)) {
		memset(line, 0, sizeof(line));
		fgets(line, sizeof(line) - 1, pf);
		ln = line;
		ln = ltrim(ln);
		ln = rtrim(ln);
		if (*ln == '\0' || *ln == '#')
			continue;

		if (strncmp(ln, "config", 6) == 0 &&
			isspace(ln[6]) &&
			strncmp((ln = ltrim(ln + 6)), "cfg", 3) == 0 &&
			(ln[3] == '\0' || isspace(ln[3]))) {
			cnf_index++;
			if (cnf_index > 0) /*only parse first 'config cfg'*/
				break;
			continue;
		}

		if (cnf_index != 0)
			continue;

		parse_option(ln, &option, &name, &value);

		if (strcmp(option, "option") != 0 || !name || !value || !(*name) || !(*value)) {
			loge("invalid option: %s %s %s\n", option, name, value);
			fclose(pf);
			return -1;
		}

		if (strcmp(name, "bind_addr") == 0 && strlen(value)) {
			if (force || !cleandns->listen_addr) {
				if (cleandns->listen_addr) free(cleandns->listen_addr);
				cleandns->listen_addr = strdup(value);
			}
		}
		else if (strcmp(name, "bind_port") == 0 && strlen(value)) {
			if (force || !cleandns->listen_port) {
				if (cleandns->listen_port) free(cleandns->listen_port);
				cleandns->listen_port = strdup(value);
			}
		}
		else if (strcmp(name, "chnroute") == 0 && strlen(value)) {
			if (force || !cleandns->chnroute_file) {
				if (cleandns->chnroute_file) free(cleandns->chnroute_file);
				cleandns->chnroute_file = strdup(value);
			}
		}
		else if (strcmp(name, "china_ip") == 0 && strlen(value)) {
			if (force || !cleandns->china_ip) {
				if (cleandns->china_ip) free(cleandns->china_ip);
				cleandns->china_ip = strdup(value);
			}
		}
		else if (strcmp(name, "foreign_ip") == 0 && strlen(value)) {
			if (force || !cleandns->foreign_ip) {
				if (cleandns->foreign_ip) free(cleandns->foreign_ip);
				cleandns->foreign_ip = strdup(value);
			}
		}
		else if (strcmp(name, "dns_server") == 0 && strlen(value)) {
			if (force || !cleandns->dns_server) {
				if (cleandns->dns_server) free(cleandns->dns_server);
				cleandns->dns_server = strdup(value);
			}
		}
		else if (strcmp(name, "compression") == 0 && strlen(value)) {
			if (force || !cleandns->compression) {
				cleandns->compression = is_true_val(value);
			}
		}
		else if (strcmp(name, "timeout") == 0 && strlen(value)) {
			if (force || cleandns->timeout <= 0) {
				cleandns->timeout = atoi(value);
			}
		}
		else if (strcmp(name, "pid_file") == 0 && strlen(value)) {
			if (force || !cleandns->pid_file) {
				if (cleandns->pid_file) free(cleandns->pid_file);
				cleandns->pid_file = strdup(value);
			}
		}
		else if (strcmp(name, "log_file") == 0 && strlen(value)) {
			if (force || !cleandns->log_file) {
				if (cleandns->log_file) free(cleandns->log_file);
				cleandns->log_file = strdup(value);
			}
		}
		else if (strcmp(name, "log_level") == 0 && strlen(value)) {
			if (force || loglevel == LOG_DEFAULT_LEVEL) {
				loglevel = atoi(value);
			}
		}
		else if (strcmp(name, "lazy") == 0 && strlen(value)) {
			if (force || !cleandns->lazy) {
				cleandns->lazy = is_true_val(value);
			}
		}
		else if (strcmp(name, "proxy") == 0 && strlen(value)) {
			if (force || !cleandns->proxy) {
				if (cleandns->proxy) free(cleandns->proxy);
				cleandns->proxy = strdup(value);
			}
		}
		else {
			/*do nothing*/
		}
	}

	fclose(pf);

#undef is_true_val

	return 0;
}

static int parse_args(cleandns_ctx *cleandns, int argc, char **argv)
{
	int ch;
	int option_index = 0;
	static struct option long_options[] = {
		{"daemon",    no_argument,       NULL, 1},
		{"pid",       required_argument, NULL, 2},
		{"log",       required_argument, NULL, 3},
		{"log-level", required_argument, NULL, 4},
		{"config",    required_argument, NULL, 5},
		{"launch-log",required_argument, NULL, 6},
		{"lazy",      no_argument,       NULL, 7},
		{"proxy",     required_argument, NULL, 8},
		{0, 0, 0, 0}
	};

	while ((ch = getopt_long(argc, argv, "hb:p:s:c:l:f:t:mvV", long_options, &option_index)) != -1) {
		switch (ch) {
		case 1:
			cleandns->daemonize = 1;
			break;
		case 2:
			if (cleandns->pid_file) free(cleandns->pid_file);
			cleandns->pid_file = strdup(optarg);
			break;
		case 3:
			if (cleandns->log_file) free(cleandns->log_file);
			cleandns->log_file = strdup(optarg);
			break;
		case 4:
			loglevel = atoi(optarg);
			break;
		case 5:
			cleandns->config_file = strdup(optarg);
			break;
		case 6:
			cleandns->launch_log = strdup(optarg);
			break;
		case 7:
            cleandns->lazy = 1;
            break;
		case 8:
			if (cleandns->proxy) free(cleandns->proxy);
			cleandns->proxy = strdup(optarg);
			break;
		case 'h':
			usage();
			exit(0);
		case 'b':
			if (cleandns->listen_addr) free(cleandns->listen_addr);
			cleandns->listen_addr = strdup(optarg);
			break;
		case 'p':
			if (cleandns->listen_port) free(cleandns->listen_port);
			cleandns->listen_port = strdup(optarg);
			break;
		case 's':
			if (cleandns->dns_server) free(cleandns->dns_server);
			cleandns->dns_server = strdup(optarg);
			break;
		case 'c':
			if (cleandns->chnroute_file) free(cleandns->chnroute_file);
			cleandns->chnroute_file = strdup(optarg);
			break;
		case 'l':
			if (cleandns->china_ip) free(cleandns->china_ip);
			cleandns->china_ip = strdup(optarg);
			break;
		case 'f':
			if (cleandns->foreign_ip) free(cleandns->foreign_ip);
			cleandns->foreign_ip = strdup(optarg);
			break;
		case 'm':
			cleandns->compression = 1;
			break;
		case 't':
			cleandns->timeout = atoi(optarg);
			break;
		case 'v':
			loglevel++;
			break;
		case 'V':
			printf(CLEANDNS_NAME " %s\n", CLEANDNS_VERSION);
			exit(0);
		default:
			usage();
			exit(1);
		}
	}

	return 0;
}

static int check_args(cleandns_ctx* cleandns)
{
	if (cleandns->dns_server == NULL) {
		cleandns->dns_server = strdup(DEFAULT_DNS_SERVER);
	}
	if (cleandns->listen_addr == NULL) {
		cleandns->listen_addr = strdup(DEFAULT_LISTEN_ADDR);
	}
	if (cleandns->listen_port == NULL) {
		cleandns->listen_port = strdup(DEFAULT_LISTEN_PORT);
	}
	if (cleandns->chnroute_file == NULL) {
		cleandns->chnroute_file = strdup(DEFAULT_CHNROUTE_FILE);
	}
	if (cleandns->china_ip && strlen(cleandns->china_ip) == 0) {
		cleandns->china_ip = NULL;
	}
	if (cleandns->foreign_ip && strlen(cleandns->foreign_ip) == 0) {
		cleandns->foreign_ip = NULL;
	}
	/*if (cleandns->china_ip == NULL && cleandns->foreign_ip == NULL) {
		printf("You should have at least one Chinese IP and one Foreign IP.\n");
		exit(1);
	}*/
	if (cleandns->timeout <= 0) {
		cleandns->timeout = atoi(DEFAULT_TIMEOUT);
	}
	if (loglevel >= LOG_DEBUG) {
		logflags = LOG_MASK_RAW;
	}
	return 0;
}

static int init_cleandns(cleandns_ctx *cleandns)
{
	if (cleandns->log_file) {
		log_file = cleandns->log_file;
		open_logfile();
	}
	else if (cleandns->launch_log) {
		log_file = cleandns->launch_log;
		open_logfile();
	}

	if (cleandns->config_file) {
		if (read_config_file(cleandns, cleandns->config_file, FALSE)) {
			return -1;
		}

		/* close, so can reopen by config file */
		if (log_file) {
			close_logfile();
			log_file = NULL;
		}

		if (cleandns->log_file) {
			log_file = cleandns->log_file;
			open_logfile();
		}
	}

	if (check_args(cleandns))
		return -1;


	if (resolve_listens(cleandns) != 0)
		return -1;

	if (cleandns->china_ip) {
		if (parse_china_ip(cleandns))
			return -1;
	}

	if (cleandns->foreign_ip) {
		if (parse_foreign_ip(cleandns))
			return -1;
	}

	if (parse_chnroute(cleandns) != 0)
		return -1;

	if (resolve_dns_server(cleandns) != 0)
		return -1;

	if (cleandns->proxy && resolve_proxy_server(cleandns) != 0)
		return -1;

	if (init_listens(cleandns) != 0)
		return -1;

	if (init_dnsservers(cleandns) != 0)
		return -1;

	if (cleandns->proxy && init_proxy_udpsock(cleandns) != 0)
		return -1;

	return 0;
}

static int cb_free_req(rbtree_t* tree, rbnode_t* x, void* state)
{
	req_t* req = x->info;

	if (req) {
		free_req(req);
		x->info = NULL;
	}

	return 0;
}

static void free_cleandns(cleandns_ctx *cleandns)
{
	int i;

	if (cleandns == NULL)
		return;

	for (i = 0; i < cleandns->listen_num; i++) {
		listen_t* listen = cleandns->listens + i;
		if (listen->sock)
			close(listen->sock);
		if (listen->addr.addrinfo) {
			freeaddrinfo(listen->addr.addrinfo);
			listen->addr.addrinfo = NULL;
		}
	}

	free(cleandns->listen_addr);
	free(cleandns->listen_port);
	free(cleandns->dns_server);
	free(cleandns->chnroute_file);
	free(cleandns->china_ip);
	free(cleandns->foreign_ip);
	free(cleandns->pid_file);
	free(cleandns->log_file);
	free(cleandns->proxy);
	free(cleandns->launch_log);
	free(cleandns->config_file);

	free(cleandns->chnroute_list.nets);
	free(cleandns->chnroute_list.nets6);

	free(cleandns->china_net.name);
	free(cleandns->china_net6.name);
	free(cleandns->foreign_net.name);
	free(cleandns->foreign_net6.name);


	for (i = 0; i < cleandns->dns_server_num; i++) {
		dns_server_t* dnsserver = cleandns->dns_servers + i;
		if (dnsserver->udpsock)
			close(dnsserver->udpsock);
		if (dnsserver->addr.addrinfo) {
			freeaddrinfo(dnsserver->addr.addrinfo);
			dnsserver->addr.addrinfo = NULL;
		}
	}

	if (cleandns->proxy_server.addr) {
		if (cleandns->proxy_server.udpsock)
			close(cleandns->proxy_server.udpsock);
		freeaddrinfo(cleandns->proxy_server.addr);
		cleandns->proxy_server.addr = NULL;
		free(cleandns->proxy_server.protocol);
	}

	rbtree_each(&cleandns->queue, cb_free_req, NULL);

	rbtree_free(&cleandns->queue);
}

static void usage()
{
  printf("%s\n", "\n"
CLEANDNS_NAME " " CLEANDNS_VERSION "\n\
\n\
Usage:\n\
\n\
cleandns [-c CHNROUTE_FILE] [-l CHINA_IP] [-f FOREIGN_IP]\n\
         [-b BIND_ADDR] [-p BIND_PORT] [-s DNS] [-t TIMEOUT] [-m]\n\
         [--config=CONFIG_PATH] [--daemon] [--pid=PID_FILE_PATH]\n\
         [--log=LOG_FILE_PATH] [--log-level=LOG_LEVEL]\n\
         [--proxy=PROXY_URL] [-v] [-V] [-h]\n\
\n\
Forward DNS requests with ECS (edns-client-subnet) support.\n\
\n\
Options:\n\
\n\
  -l CHINA_IP           China ip address, e.g. 114.114.114.114/24.\n\
                        Use comma to separate IPv4 and IPv6,\n\
                        e.g. 114.114.114.114/24,2405:2d80::/32.\n\
  -f FOREIGN_IP         Foreign ip address, e.g. 8.8.8.8/24.\n\
                        Use comma to separate IPv4 and IPv6,\n\
                        e.g. 8.8.8.8/24,2001:df2:8300::/48.\n\
  -c CHNROUTE_FILE      Path to china route file, default: " DEFAULT_CHNROUTE_FILE ".\n\
                        Use comma to separate multi files, e.g. chnroute_ipv4.txt,chnroute_ipv6.txt.\n\
  -b BIND_ADDR          Address that listens, default: " DEFAULT_LISTEN_ADDR ".\n\
                        Use comma to separate multi addresses, e.g. 127.0.0.1:5354,[::1]:5354.\n\
  -p BIND_PORT          Port that listen on, default: " DEFAULT_LISTEN_PORT ".\n\
                        The port specified in \"-b\" is priority .\n\
  -s DNS                DNS server to use, default: " DEFAULT_DNS_SERVER ".\n\
                        tcp://IP[:PORT] means forward request to upstream by TCP protocol,\n\
                        [udp://]IP[:PORT] means forward request to upstream by UDP protocol.\n\
                        Forward by UDP protocol default, and default port of upstream is 53.\n\
  -m                    Use DNS compression pointer mutation, only available on foreign dns server.\n\
  -t TIMEOUT            Timeout, default: " DEFAULT_TIMEOUT ".\n\
  --daemon              Daemonize.\n\
  --pid=PID_FILE_PATH   pid file, default: " DEFAULT_PID_FILE ", only available on daemonize.\n\
  --log=LOG_FILE_PATH   Write log to a file.\n\
  --log-level=LOG_LEVEL Log level, range: [0, 7], default: " LOG_DEFAULT_LEVEL_NAME ".\n\
  --config=CONFIG_PATH  Config file, find sample at https://github.com/GangZhuo/CleanDNS.\n\
  --lazy                Disable pollution detection.\n\
  --proxy=PROXY_URL     Proxy server, e.g. socks5://127.0.0.1:1080, only available on foreign dns server.\n\
                        Now, only socks5 with no authentication is supported.\n\
  -v                    Verbose logging.\n\
  -h                    Show this help message and exit.\n\
  -V                    Print version and then exit.\n\
\n\
Online help: <https://github.com/GangZhuo/CleanDNS>\n");
}

static void syslog_writefile(int mask, const char* fmt, va_list args)
{
	char buf[640], buf2[1024];
	int len;
	int level = log_level_comp(mask);
	char date[32];
	const char* extra_msg;
	time_t now;

	memset(buf, 0, sizeof(buf));
	len = vsnprintf(buf, sizeof(buf) - 1, fmt, args);

	now = time(NULL);

	strftime(date, sizeof(date), LOG_TIMEFORMAT, localtime(&now));
	extra_msg = log_priorityname(level);

	memset(buf2, 0, sizeof(buf2));

	if (extra_msg && strlen(extra_msg)) {
		len = snprintf(buf2, sizeof(buf2) - 1, "%s [%s] %s", date, extra_msg, buf);
	}
	else {
		len = snprintf(buf2, sizeof(buf2) - 1, "%s %s", date, buf);
	}

	if (len > 0) {
		FILE* pf;
		pf = fopen(log_file, "a+");
		if (pf) {
			fwrite(buf2, 1, len, pf);
			fclose(pf);
		}
		else {
			printf("cannot open %s\n", log_file);
		}
	}
}

static void syslog_vprintf(int mask, const char* fmt, va_list args)
{
#ifdef WINDOWS
	logw("syslog_vprintf(): not implemented in Windows port");
#else
	char buf[640];
	int priority = log_level_comp(mask);

	memset(buf, 0, sizeof(buf));
	vsnprintf(buf, sizeof(buf) - 1, fmt, args);
	syslog(priority, "%s", buf);
#endif
}

static void open_logfile()
{
	if (log_file) {
		log_vprintf = syslog_writefile;
		log_vprintf_with_timestamp = syslog_writefile;
	}
}

static void close_logfile()
{
	if (log_file) {
		log_vprintf = log_default_vprintf;
		log_vprintf_with_timestamp = log_default_vprintf_with_timestamp;
		log_file = NULL;
	}
}

static void open_syslog()
{
#ifdef WINDOWS
	logw("use_syslog(): not implemented in Windows port");
#else
	openlog(CLEANDNS_NAME, LOG_CONS | LOG_PID, LOG_DAEMON);
	is_use_syslog = 1;
	log_vprintf = syslog_vprintf;
	log_vprintf_with_timestamp = syslog_vprintf;
#endif
}

static void close_syslog()
{
#ifdef WINDOWS
	logw("close_syslog(): not implemented in Windows port");
#else
	if (is_use_syslog) {
		is_use_syslog = 0;
		log_vprintf = log_default_vprintf;
		log_vprintf_with_timestamp = log_default_vprintf_with_timestamp;
		closelog();
	}
#endif
}

#ifdef WINDOWS

static void ServiceMain(int argc, char** argv)
{
	BOOL bRet;
	bRet = TRUE;

	ServiceStatus.dwServiceType = SERVICE_WIN32;
	ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

	ServiceStatus.dwWin32ExitCode = 0;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	ServiceStatus.dwCheckPoint = 0;
	ServiceStatus.dwWaitHint = 0;

	hStatus = RegisterServiceCtrlHandler(CLEANDNS_NAME, (LPHANDLER_FUNCTION)ControlHandler);
	if (hStatus == (SERVICE_STATUS_HANDLE)0)
	{
		loge("ServiceMain(): cannot register service ctrl handler");
		return;
	}

	ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(hStatus, &ServiceStatus);

	if (init_cleandns(s_cleandns) != 0)
		return;

	print_args(s_cleandns);

	if (do_loop(s_cleandns) != 0)
		return;

	free_cleandns(s_cleandns);

	if (log_file) {
		close_logfile();
	}
}

static void ControlHandler(DWORD request)
{
	switch (request) {
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
		running = 0;
		free_cleandns(s_cleandns);
		if (is_use_syslog) {
			close_syslog();
		}
		ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		ServiceStatus.dwWin32ExitCode = 0;
		SetServiceStatus(hStatus, &ServiceStatus);
		break;
	default:
		SetServiceStatus(hStatus, &ServiceStatus);
		break;
	}
}

#endif

static void run_as_daemonize(cleandns_ctx* cleandns)
{
#ifdef WINDOWS
	SERVICE_TABLE_ENTRY ServiceTable[2];

	ServiceTable[0].lpServiceName = CLEANDNS_NAME;
	ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

	ServiceTable[1].lpServiceName = NULL;
	ServiceTable[1].lpServiceProc = NULL;

	if (!StartServiceCtrlDispatcher(ServiceTable)) {
		loge("run_as_daemonize(): cannot start service ctrl dispatcher");
	}
#else
	pid_t pid, sid;
	int dev_null;

	if (!cleandns->pid_file) {
		cleandns->pid_file = strdup(DEFAULT_PID_FILE);
	}

	pid = fork();
	if (pid < 0) {
		exit(1);
	}

	if (pid > 0) {
		if (cleandns->pid_file) {
			FILE* file = fopen(cleandns->pid_file, "w");
			if (file == NULL) {
				logc("Invalid pid file: %s\n", cleandns->pid_file);
				exit(1);
			}
			fprintf(file, "%d", (int)pid);
			fclose(file);
		}
		
		exit(0);
	}

	if (init_cleandns(cleandns) != 0)
		exit(1);

	umask(0);

	if (!log_file) {
		open_syslog();
	}

	sid = setsid();
	if (sid < 0) {
		exit(1);
	}

	if ((chdir("/")) < 0) {
		exit(1);
	}

	dev_null = open("/dev/null", O_WRONLY);
	if (dev_null) {
		dup2(dev_null, STDOUT_FILENO);
		dup2(dev_null, STDERR_FILENO);
	}
	else {
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	close(STDIN_FILENO);

	print_args(cleandns);

	if (do_loop(cleandns) != 0)
		exit(1);

	free_cleandns(cleandns);

	if (log_file) {
		close_logfile();
	}
	
	if (is_use_syslog) {
		close_syslog();
	}

#endif
}
