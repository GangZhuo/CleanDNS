#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>

#ifndef WINDOWS
#include <signal.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif


#include "log.h"
#include "cleandns.h"
#include "ns_msg.h"
#include "stream.h"

#define CLEANDNS_VERSION "0.1"

#define DEFAULT_DNS_SERVER "8.8.8.8,119.29.29.29"
#define DEFAULT_LISTEN_ADDR "0.0.0.0"
#define DEFAULT_LISTEN_PORT "53"
#define DEFAULT_CHNROUTE_FILE "chnroute.txt"
#define DEFAULT_TIMEOUT "6"

#define FLG_NONE		0
#define FLG_POLLUTE		1
#define FLG_A			(1 << 1)
#define FLG_A_CHN		(1 << 2)
#define FLG_AAAA		(1 << 3)
#define FLG_AAAA_CHN	(1 << 4)
#define FLG_PTR			(1 << 5)
#define FLG_OPT			(1 << 6)

#define MAX(a, b) (((a) < (b)) ? (b) : (a))
#define fix_reqid(pid, num) ((*pid) = ((*pid) / (2 * (num))) * (num) * 2)
#define ext_num(msgid, num) ((msgid) - (((msgid) / (2 * num) ) * (num) * 2))
#define is_foreign(msgid, num) (ext_num((msgid), (num)) >= (num))
#define dns_index(msgid, num) ((ext_num((msgid), (num)) >= (num)) ? (ext_num((msgid), (num)) - (num)) : (ext_num((msgid), (num))))

typedef struct {
	time_t now;
	rbnode_list_t *expired_nodes;
	cleandns_ctx *cleandns;
} timeout_handler_ctx;

static int running = 0;

static void usage();
static int init_cleandns(cleandns_ctx *cleandns);
static void free_cleandns(cleandns_ctx *cleandns);
static int parse_args(cleandns_ctx *cleandns, int argc, char **argv);
static int parse_chnroute(cleandns_ctx *cleandns);
static int test_ip_in_list(struct in_addr *ip, const net_list_t *netlist);
static int resolve_dns_server(cleandns_ctx *cleandns);
static int init_sockets(cleandns_ctx *cleandns);
static int do_loop(cleandns_ctx *cleandns);
static int handle_listen_sock(cleandns_ctx *cleandns);
static int handle_remote_sock(cleandns_ctx *cleandns);
static int handle_timeout(cleandns_ctx *cleandns);
static char *get_addrname(struct sockaddr *addr);
static int parse_netmask(net_mask_t *netmask, char *line);

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
		exit(1);  // for gprof
	else
		running = 0;
}
#endif

int main(int argc, char **argv)
{
	cleandns_ctx cleandns = { 0 };

#ifdef WINDOWS
	win_init();
#endif

	if (init_cleandns(&cleandns) != 0)
		return EXIT_FAILURE;

	if (parse_args(&cleandns, argc, argv) != 0)
		return EXIT_FAILURE;

	if (cleandns.china_ip) {
		if (ns_ecs_parse_subnet((struct sockaddr *)(&cleandns.china_net.addr),
			&cleandns.china_net.mask, cleandns.china_ip) != 0) {
			loge("Invalid addr %s\n", cleandns.china_ip);
			return EXIT_FAILURE;
		}
		cleandns.china_net.name = cleandns.china_ip;
	}

	if (cleandns.foreign_ip) {
		if (ns_ecs_parse_subnet((struct sockaddr *)(&cleandns.foreign_net.addr),
			&cleandns.foreign_net.mask, cleandns.foreign_ip) != 0) {
			loge("Invalid addr %s\n", cleandns.foreign_ip);
			return EXIT_FAILURE;
		}
		cleandns.foreign_net.name = cleandns.foreign_ip;
	}

	if (parse_chnroute(&cleandns) != 0)
		return EXIT_FAILURE;

	if (resolve_dns_server(&cleandns) != 0)
		return EXIT_FAILURE;

	if (cleandns.compression) {
		int i;
		struct sockaddr_in* dns_addr;
		struct in_addr* dns_ip;
		for (i = 0; i < cleandns.dns_server_num; i++) {
			dns_addr = (struct sockaddr_in*)
				cleandns.dns_server_addr[i]->ai_addr;
			dns_ip = (struct in_addr*)&dns_addr->sin_addr;
			/* only foreign dns server need compression*/
			if (!test_ip_in_list(dns_ip, &cleandns.chnroute_list)) {
				cleandns.dns_server_cmp[i] = 1;
			}
			else {
				cleandns.dns_server_cmp[i] = 0;
			}
		}
	}

	if (init_sockets(&cleandns) != 0)
		return EXIT_FAILURE;

	srand((unsigned int)time(NULL));

#ifdef WINDOWS
	if (0 == SetConsoleCtrlHandler((PHANDLER_ROUTINE)sig_handler, TRUE)) {
		loge("can not set control handler\n");
		return EXIT_FAILURE;
	}
#else
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
#endif

    logn("listen on %s:%s\n", cleandns.listen_addr, cleandns.listen_port);
    logn("dns server: %s\n", cleandns.dns_server);
    logn("chnroute: %s\n", cleandns.chnroute_file);
    logn("china ip: %s\n", cleandns.china_ip);
    logn("foreign ip: %s\n", cleandns.foreign_ip);
    logn("compression: %s\n", cleandns.compression ? "on" : "off");
    logn("timeout: %d\n", cleandns.timeout);
    logn("loglevel: %d\n", loglevel);

	if (do_loop(&cleandns) != 0)
		return EXIT_FAILURE;

	free_cleandns(&cleandns);

    return EXIT_SUCCESS;
}

static int do_loop(cleandns_ctx *cleandns)
{
	fd_set readset, errorset;
	int max_fd;

	running = 1;
	max_fd = MAX(cleandns->listen_sock, cleandns->remote_sock) + 1;
	while (running) {
		FD_ZERO(&readset);
		FD_ZERO(&errorset);
		FD_SET(cleandns->listen_sock, &readset);
		FD_SET(cleandns->listen_sock, &errorset);
		FD_SET(cleandns->remote_sock, &readset);
		FD_SET(cleandns->remote_sock, &errorset);
		struct timeval timeout = {
			.tv_sec = 0,
			.tv_usec = 50 * 1000,
		};
		if (select(max_fd, &readset, NULL, &errorset, &timeout) == -1) {
			loge("select\n");
			return -1;
		}
		if (FD_ISSET(cleandns->listen_sock, &errorset)) {
			loge("listen_sock error\n");
			return -1;
		}
		if (FD_ISSET(cleandns->remote_sock, &errorset)) {
			loge("remote_sock error\n");
			return -1;
		}
		if (FD_ISSET(cleandns->listen_sock, &readset))
			handle_listen_sock(cleandns);
		if (FD_ISSET(cleandns->remote_sock, &readset))
			handle_remote_sock(cleandns);
		handle_timeout(cleandns);
	}

	return 0;
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
			struct in_addr6 *addr = (struct in_addr6 *)rr->rdata;
			static char ipname[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, addr, ipname, INET6_ADDRSTRLEN);
			r = stream_writef(s, len > 0 ? ", %s" : "%s", ipname);
			if (r < 0)
				return -1;
			len += r;
		}
		else if (rr->type == NS_QTYPE_PTR) {
			r = stream_writef(s, len > 0 ? ", %s" : "%s", rr->rdata);
			if (r < 0)
				return -1;
			len += r;
		}
		else if (rr->type == NS_QTYPE_CNAME) {
			/*r = stream_writef(s, len > 0 ? ", cname: %s" : "cname: %s", rr->rdata);
			if (r < 0)
				return -1;
			len += r;*/
		}
		else if (rr->type == NS_QTYPE_SOA) {
			/*ns_soa_t *soa = rr->rdata;
			r = stream_writef(s, len > 0 ? ", ns1: %s, ns2: %s" : "ns1: %s, ns2: %s", soa->mname, soa->rname);
			if (r < 0)
				return -1;
			len += r;*/
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
	stream_t rq = STREAM_INIT();
	stream_t rs = STREAM_INIT();
	get_questions(&rq, msg);
	get_answers(&rs, msg);
	logi("recv response %s from %s (%s): %s\n",
		rq.array,
		from_addr ? get_addrname(from_addr) : "",
		is_foreign(msg->id, cleandns->dns_server_num) ? "foreign" : "china",
		rs.array);
	stream_free(&rq);
	stream_free(&rs);
}

static int send_nsmsg(cleandns_ctx *cleandns, ns_msg_t *msg,
	int compression, subnet_t *subnet,
	sock_t sock, struct sockaddr *to, socklen_t tolen)
{
	stream_t s = STREAM_INIT();
	int len;

	if (subnet) {
        ns_rr_t *rr;
		rr = ns_find_edns(msg);
        if (rr == NULL) {
            rr = ns_add_edns(msg);
            if (rr == NULL) {
                loge("send_nsmsg: Can't add edns\n");
                return -1;
            }
        }

		rr->cls = NS_PAYLOAD_SIZE; /* set edns payload size */

        if (ns_edns_set_ecs(rr, (struct sockaddr *)&subnet->addr, subnet->mask, 0) != 0) {
            loge("send_nsmsg: Can't set ecs\n");
            return -1;
        }
	}

	if (loglevel >= LOG_INFO) {
		if (msg->ancount > 0) {
			stream_t questions = STREAM_INIT();
			stream_t answers = STREAM_INIT();
			get_questions(&questions, msg);
			get_answers(&answers, msg);
			logi("send msg to '%s': questions=%s, answers=%s\n",
				get_addrname(to),
				questions.array,
				answers.array);
			stream_free(&questions);
			stream_free(&answers);
		}
		else if (subnet)
			logi("send msg to '%s' with '%s'\n", get_addrname(to), subnet->name);
		else {
			logi("send msg to '%s'\n", get_addrname(to));
		}
	}

	if ((len = ns_serialize(&s, msg, compression)) <= 0) {
		loge("send_nsmsg: Can't serialize the 'msg'\n");
		stream_free(&s);
		return -1;
	}

	if (loglevel > LOG_DEBUG) {
		logd("send data:\n");
		bprint(s.array, s.size);
		logd("\n");
	}

	if (sendto(sock, s.array, s.size, 0, to, tolen) == -1) {
		loge("send_nsmsg: Can't send data to '%s'\n",
			cleandns->dns_server);
		stream_free(&s);
		return -1;
	}

	stream_free(&s);

	return 0;
}

static int handle_listen_sock_recv_nsmsg(cleandns_ctx *cleandns, ns_msg_t *msg, req_t *req)
{
	int i;

	if (loglevel >= LOG_DEBUG) {
		logd("request msg:\n");
		ns_print(msg);
	}

	if (cleandns->china_ip == NULL && cleandns->foreign_ip == NULL) {
		for (i = 0; i < cleandns->dns_server_num; i++) {
			msg->id = (uint16_t)(req->id + i);
			if (send_nsmsg(cleandns, msg, cleandns->dns_server_cmp[i], NULL,
				cleandns->remote_sock, cleandns->dns_server_addr[i]->ai_addr,
				cleandns->dns_server_addr[i]->ai_addrlen) != 0) {
				loge("handle_listen_sock_recv_nsmsg: failed to send 'msg' with 'china_ip'.\n");
			}
			else {
				req->wait_num++;
			}
		}
		
	}
	else {
		if (cleandns->china_ip) {
			for (i = 0; i < cleandns->dns_server_num; i++) {
				msg->id = (uint16_t)(req->id + i);
				if (send_nsmsg(cleandns, msg, cleandns->dns_server_cmp[i], &cleandns->china_net,
					cleandns->remote_sock, cleandns->dns_server_addr[i]->ai_addr,
					cleandns->dns_server_addr[i]->ai_addrlen) != 0) {
					loge("handle_listen_sock_recv_nsmsg: failed to send 'msg' with 'china_ip'.\n");
				}
				else {
					req->wait_num++;
				}
			}
		}

		if (cleandns->foreign_ip) {
			for (i = 0; i < cleandns->dns_server_num; i++) {
				msg->id = (uint16_t)(req->id + cleandns->dns_server_num + i);
				if (send_nsmsg(cleandns, msg, cleandns->dns_server_cmp[i], &cleandns->foreign_net,
					cleandns->remote_sock, cleandns->dns_server_addr[i]->ai_addr,
					cleandns->dns_server_addr[i]->ai_addrlen) != 0) {
					loge("handle_listen_sock_recv_nsmsg: failed to send 'msg' with 'foreign_ip'.\n");
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
        req->edns = (ns_find_edns(&msg) != NULL);

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

static int handle_listen_sock(cleandns_ctx *cleandns)
{
	int len;
    req_t *req;

    req = new_req();
    if (req == NULL) {
        loge("handle_listen_sock: new_req()\n");
        return -1;
    }

	req->expire = time(NULL) + cleandns->timeout;

    if (queue_add(cleandns, req) != 0) {
        loge("handle_listen_sock_recv: Can't add 'req' to queue\n");
        free_req(req);
        return -1;
    }

    len = recvfrom(cleandns->listen_sock, cleandns->buf, NS_PAYLOAD_SIZE, 0,
            (struct sockaddr *)(&req->addr), &req->addrlen);
    if (len > 0) {

		if (loglevel > LOG_DEBUG) {
			logd("request data:\n");
			bprint(cleandns->buf, len);
			logd("\n");
		}
		
		if (handle_listen_sock_recv(cleandns, req, len) != 0) {
           loge("handle_listen_sock: handle_listen_sock_recv()\n");
           queue_remove(cleandns, req);
           free_req(req);
           return -1;
       }
       else
           return 0;
    }
    else {
        loge("handle_listen_sock: recvfrom()\n");
        queue_remove(cleandns, req);
        free_req(req);
        return -1;
    }
}

static int check_rr(cleandns_ctx *cleandns, ns_rr_t *rr)
{
	if (rr->type == NS_QTYPE_A) {
		struct in_addr *addr = (struct in_addr *)rr->rdata;
		if (test_ip_in_list(addr, &cleandns->chnroute_list)) {
			return FLG_A_CHN;
		}
		else {
			return FLG_A;
		}
	}
	else if (rr->type == NS_QTYPE_AAAA) {
		struct in_addr6 *addr = (struct in_addr6 *)rr->rdata;
		return FLG_AAAA;
	}
	else if (rr->type == NS_QTYPE_PTR) {
		return FLG_PTR;
	}
	else if (rr->type == NS_QTYPE_OPT) {
		return FLG_OPT;
	}
	return FLG_NONE;
}

static int check_ns_msg(cleandns_ctx *cleandns, ns_msg_t *msg)
{
	int i, rrcount, flags = 0;
	ns_rr_t *rr;

	if (msg->arcount == 0)
		return FLG_POLLUTE;
	
	rrcount = msg->ancount + msg->nscount;
	for (i = 0; i < rrcount; i++) {
		rr = msg->rrs + i;
		flags |= check_rr(cleandns, rr);

		if (flags & FLG_OPT) /* edns should be in additional records section */
			return FLG_POLLUTE;
	}

	rrcount = ns_rrcount(msg);
	for (; i < rrcount; i++) {
		rr = msg->rrs + i;
		flags |= check_rr(cleandns, rr);
	}

	return flags;
}

static int response_best_nsmsg(cleandns_ctx* cleandns, req_t* req)
{
	ns_msg_t* best = NULL;

	if (req->ns_msg_num == 0) {
		loge("%s: resolve failed.\n", req->questions);
		return -1;
	}
	else {

		int score[MAX_NS_MSG] = { 0 };
		int i, flags, best_index = 0;
		ns_msg_t* msg;
		struct sockaddr_in* dns;

		for (i = 0; i < req->ns_msg_num; i++) {
			msg = req->ns_msg + i;
			dns = (struct sockaddr_in*)
				cleandns->dns_server_addr[dns_index(msg->id, cleandns->dns_server_num)]->ai_addr;

			flags = check_ns_msg(cleandns, msg);
			if (flags & FLG_POLLUTE) {
				if (loglevel >= LOG_INFO) {
					logi("response_best_nsmsg: polluted msg (#%d)\n", i);
				}
				score[i] = -1;
			}
			else if (req->edns && !(flags & FLG_OPT)) {
				if (loglevel >= LOG_INFO) {
					logi("response_best_nsmsg: no edns msg (#%d)\n", i);
				}
			}
			else {
				/* chose a best msg */
				int haveip;
				haveip = (flags & (FLG_A | FLG_AAAA | FLG_A_CHN | FLG_AAAA_CHN));
				if (haveip) {
					int chnip, chnsubnet, chndns;
					struct in_addr* addr = &dns->sin_addr;

					chnip = (flags & (FLG_A_CHN | FLG_AAAA_CHN)); /* have chinese ip(s) in result */
					chnsubnet = !is_foreign(msg->id, cleandns->dns_server_num); /* edns-client-subnet with chinese ip */
					chndns = test_ip_in_list(addr, &cleandns->chnroute_list); /* from china dns server */

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
			dns = (struct sockaddr_in*)
				cleandns->dns_server_addr[dns_index(best->id, cleandns->dns_server_num)]->ai_addr;
			logi("best answers come from '%s'\n",
				get_addrname((struct sockaddr*)dns));
		}
	}

	if (best) {
		int rc = -1;

		best->id = req->old_id;
		if (!req->edns) {
			ns_remove_edns(best);
		}
		else {
			/*TODO: restore client ip*/
		}

		if (send_nsmsg(cleandns, best, 0, NULL, cleandns->listen_sock,
			(struct sockaddr*)(&req->addr), req->addrlen) != 0) {
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

	if (loglevel >= LOG_DEBUG) {
		logd("response msg:\n");
		ns_print(msg);
	}

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
	else if (req->edns && !(flags & FLG_OPT)) {
		if (loglevel >= LOG_INFO) {
			logi("handle_remote_sock_recv_nsmsg: drop msg base on no edns msg\n");
		}
		return 0;
	}

	if (req->ns_msg_num < MAX_NS_MSG) {
		/* save msg */
		memcpy(req->ns_msg + (req->ns_msg_num++), msg, sizeof(ns_msg_t));

		/* clear, so there do not free the copied files when 'ns_msg_free(msg)' */
		memset(msg, 0, sizeof(ns_msg_t));
	}

	if (req->ns_msg_num >= req->wait_num) {
		queue_remove_bynode(cleandns, reqnode);
		return response_best_nsmsg(cleandns, req);
	}

	return 0;
}

static int handle_remote_sock_recv(cleandns_ctx *cleandns, int len, struct sockaddr *from_addr)
{
	ns_msg_t msg;
	int rc = -1;

	if (init_ns_msg(&msg) != 0) {
		loge("handle_remote_sock_recv: init_ns_msg()\n");
		return -1;
	}

	if (ns_parse(&msg, (uint8_t *)cleandns->buf, len) == 0) {

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

static int handle_remote_sock(cleandns_ctx *cleandns)
{
	struct sockaddr_storage from_addr;
	socklen_t from_addrlen = sizeof(struct sockaddr_storage);
	int len;

	memset(&from_addr, 0, sizeof(struct sockaddr_storage));

	len = recvfrom(cleandns->remote_sock, cleandns->buf, NS_PAYLOAD_SIZE, 0,
            (struct sockaddr *)&from_addr, &from_addrlen);

	if (len > 0) {

		if (loglevel > LOG_DEBUG) {
			logd("response data:\n");
			bprint(cleandns->buf, len);
			logd("\n");
		}
		
		if (handle_remote_sock_recv(cleandns, len, (struct sockaddr *)&from_addr) != 0) {
           loge("handle_remote_sock: handle_remote_sock_recv()\n");
           return -1;
       }
       else
           return 0;
    }
    else {
        loge("handle_remote_sock: recvfrom()\n");
        return -1;
    }
}

static int cb_each_rbnode(rbtree_t *tree, rbnode_t *x, void *state)
{
	timeout_handler_ctx *ctx = state;
	req_t *req = x->info;
	
	if (req->expire <= ctx->now) {
		rbnode_list_add(ctx->expired_nodes, x);
	}

	return 0;
}

static int handle_timeout(cleandns_ctx *cleandns)
{
	timeout_handler_ctx ctx;
	rbnode_list_item_t *item;
	rbnode_t *n;
	req_t *req;

	ctx.cleandns = cleandns;
	ctx.now = time(NULL);
	ctx.expired_nodes = rbnode_list_create();

	if (ctx.expired_nodes == NULL) {
		loge("handle_timeout: rbnode_list_create()\n");
		return -1;
	}

	rbtree_each(&cleandns->queue, cb_each_rbnode, &ctx);

	item = ctx.expired_nodes->items;
	while (item) {
		n = item->node;
		req = n->info;
		item = item->next;

		queue_remove_bynode(cleandns, n);

		if (loglevel >= LOG_INFO) {
			logi("timeout: questions=%s\n",
				req->questions);
		}

		response_best_nsmsg(cleandns, req);

	}

	rbnode_list_destroy(ctx.expired_nodes);

	return 0;
}

static int setnonblock(sock_t sock)
{
#ifdef WINDOWS
	int iResult;
	// If iMode!=0, non-blocking mode is enabled.
	u_long iMode = 1;
	iResult = ioctlsocket(sock, FIONBIO, &iMode);
	if (iResult != NO_ERROR) {
		loge("ioctlsocket failed with error: %ld\n", iResult);
		return -1;
	}
#else
	int flags;
	flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1) {
		loge("fcntl\n");
		return -1;
	}
	if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
		loge("fcntl\n");
		return -1;
	}
#endif

	return 0;
}

static int init_sockets(cleandns_ctx *cleandns)
{
	struct addrinfo hints;
	struct addrinfo *addr_ip;
	int r;

	cleandns->listen_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (setnonblock(cleandns->listen_sock) != 0)
		return -1;
#ifdef WINDOWS
	disable_udp_connreset(cleandns->listen_sock);
#endif
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	if ((r = getaddrinfo(cleandns->listen_addr, cleandns->listen_port, &hints, &addr_ip)) != 0) {
		loge("%s:%s:%s\n", gai_strerror(r), cleandns->listen_addr, cleandns->listen_port);
		return -1;
	}
	if (bind(cleandns->listen_sock, addr_ip->ai_addr, addr_ip->ai_addrlen) != 0) {
		loge("Can't bind address %s:%s\n", cleandns->listen_addr, cleandns->listen_port);
		return -1;
	}
	freeaddrinfo(addr_ip);

	cleandns->remote_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (setnonblock(cleandns->remote_sock) != 0)
		return -1;
#ifdef WINDOWS
	disable_udp_connreset(cleandns->remote_sock);
#endif
	return 0;
}

static int resolve_dns_server(cleandns_ctx *cleandns)
{
	struct addrinfo hints;
	char *s, *ip, *port, *p;
	int r;

	s = strdup(cleandns->dns_server);

	for (p = strtok(s, ",");
		p && *p && cleandns->dns_server_num < MAX_DNS_SERVER;
		p = strtok(NULL, ",")) {

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;

		ip = p;
		port = strrchr(p, ':');
		if (port) {
			*port = '\0';
			port++;
		}
		else {
			port = "53";
		}

		if ((r = getaddrinfo(ip, port, &hints,
				cleandns->dns_server_addr + cleandns->dns_server_num)) != 0) {
			loge("%s: %s:%s\n", gai_strerror(r), ip, port);
			free(s);
			return -1;
		}
		cleandns->dns_server_num++;
	}

	free(s);

	if (cleandns->dns_server_num == 0) {
		loge("no dns server\n");
		return -1;
	}
	
	return 0;
}

static int cmp_net_mask(const void *a, const void *b)
{
	return ((net_mask_t *)a)->net - ((net_mask_t *)b)->net;
}

static int test_ip_in_list(struct in_addr *ip, const net_list_t *netlist)
{
	int l = 0, r = netlist->entries - 1;
	int m, cmp;
	net_mask_t ip_net;
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
    if ((netlist->nets[l].net ^ ip_net.net) &
            (UINT32_MAX ^ netlist->nets[l].mask)) {
        return 0;
    }
    return 1;
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
        snprintf(addrname, sizeof(addrname), "%s:%d", sip,
                (int)(htons(addr_in6->sin6_port) & 0xFFFF));
	}
    else {
        addrname[0] = '\0';
    }
    return addrname;
}

static int parse_netmask(net_mask_t *netmask, char *line)
{
    char *sp_pos;
    struct in_addr ip;
    sp_pos = strchr(line, '/');
    if (sp_pos) {
        *sp_pos = 0;
        netmask->mask = (1 << (32 - atoi(sp_pos + 1))) - 1;
    }
    else {
        netmask->mask = UINT32_MAX;
    }
    if (inet_pton(AF_INET, line, &ip) == 0) {
        if (sp_pos) *sp_pos = '/';
        loge("invalid addr %s\n", line);
        return -1;
    }
    netmask->net = ntohl(ip.s_addr);
    if (sp_pos) *sp_pos = '/';
    return 0;
}

static int parse_chnroute(cleandns_ctx *cleandns)
{
	char buf[32];
	size_t buf_size;
	char *line;
	net_list_t *list;
	FILE *fp;
	int i;

	buf_size = sizeof(buf);
	list = &cleandns->chnroute_list;
	list->entries = 0;
	i = 0;

	fp = fopen(cleandns->chnroute_file, "rb");
	if (fp == NULL) {
		loge("Can't open chnroute: %s\n", cleandns->chnroute_file);
		return -1;
	}

	while ((line = fgets(buf, buf_size, fp)) != NULL) {
		list->entries++;
	}

	list->nets = calloc(list->entries, sizeof(net_mask_t));
	if (list->nets == NULL) {
		loge("calloc\n");
		return -1;
	}

	if (fseek(fp, 0, SEEK_SET) != 0) {
		loge("fseek\n");
		return -1;
	}

	while ((line = fgets(buf, buf_size, fp)) != NULL) {
		char *sp_pos;
		sp_pos = strchr(line, '\r');
		if (sp_pos) *sp_pos = 0;
		sp_pos = strchr(line, '\n');
		if (sp_pos) *sp_pos = 0;
        if (parse_netmask(list->nets + i, line) != 0) {
            loge("invalid addr %s in %s:%d\n", line, cleandns->chnroute_file, i + 1);
            return -1;
        }
        i++;
    }

	qsort(list->nets, list->entries, sizeof(net_mask_t), cmp_net_mask);

	fclose(fp);
	return 0;
}

static int parse_args(cleandns_ctx *cleandns, int argc, char **argv)
{
	int ch;
	while ((ch = getopt(argc, argv, "hb:p:s:c:l:f:t:mvV")) != -1) {
		switch (ch) {
		case 'h':
			usage();
			exit(0);
		case 'b':
			cleandns->listen_addr = strdup(optarg);
			break;
		case 'p':
			cleandns->listen_port = strdup(optarg);
			break;
		case 's':
			cleandns->dns_server = strdup(optarg);
			break;
		case 'c':
			cleandns->chnroute_file = strdup(optarg);
			break;
		case 'l':
			cleandns->china_ip = strdup(optarg);
			break;
		case 'f':
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
			printf("CleanDNS %s\n", CLEANDNS_VERSION);
			exit(0);
		default:
			usage();
			exit(1);
		}
	}
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
	if (loglevel > LOG_DEBUG) {
		logflags = LOG_MASK_RAW;
	}
	return 0;
}

static int init_cleandns(cleandns_ctx *cleandns)
{
	memset(cleandns, 0, sizeof(cleandns_ctx));

	if (rbtree_init(&cleandns->queue) != 0)
		return -1;

	return 0;
}

static void free_cleandns(cleandns_ctx *cleandns)
{
	int i;
	if (cleandns->listen_sock)
		close(cleandns->listen_sock);
	if (cleandns->remote_sock)
		close(cleandns->remote_sock);
	free(cleandns->listen_addr);
	free(cleandns->listen_port);
	free(cleandns->dns_server);
	free(cleandns->chnroute_file);
	free(cleandns->china_ip);
	free(cleandns->foreign_ip);
	
	for (i = 0; i < cleandns->dns_server_num; i++) {
		freeaddrinfo(cleandns->dns_server_addr[i]);
	}

	rbtree_free(&cleandns->queue);
}

static void usage()
{
  printf("%s\n", "\
usage: cleandns [-h] [-l CHINA_IP] [-f FOREIGN_IP] [-b BIND_ADDR]\n\
       [-p BIND_PORT] [-c CHNROUTE_FILE] [-s DNS] [-m] [-v] [-V]\n\
Forward DNS requests.\n\
\n\
  -l CHINA_IP         china ip address, e.g. 114.114.114.114/24\n\
  -f FOREIGN_IP       foreign ip address, e.g. 8.8.8.8/24\n\
  -c CHNROUTE_FILE    path to china route file, default:\n\
                      " DEFAULT_CHNROUTE_FILE "\n\
  -b BIND_ADDR        address that listens, default: " DEFAULT_LISTEN_ADDR "\n\
  -p BIND_PORT        port that listens, default: " DEFAULT_LISTEN_PORT "\n\
  -s DNS              DNS server to use, default:\n\
                      " DEFAULT_DNS_SERVER "\n\
  -m                  use DNS compression pointer mutation\n\
  -t                  timeout, default: " DEFAULT_TIMEOUT "\n\
  -v                  verbose logging\n\
  -h                  show this help message and exit\n\
  -V                  print version and exit\n\
\n\
Online help: <https://github.com/GangZhuo/CleanDNS>\n");
}
