#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../src/ns_msg.h"
#include "../src/log.h"
#include "../src/stream.h"
#include "../src/rbtree.h"
/*
0x13, 0xE5, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x03,
0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01


*/
static uint8_t ns_msg_bytes[] = {
	0x00, 0x82, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
	0x00, 0x01, 0x00, 0x00, 0x04, 0x69, 0x70, 0x76,
	0x36, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
	0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00,
	0x01, 0x51, 0x6c, 0x00, 0x09, 0x04, 0x69, 0x70,
	0x76, 0x36, 0x01, 0x6c, 0xc0, 0x11, 0xc0, 0x32,
	0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x28,
	0x00, 0x26, 0x03, 0x6e, 0x73, 0x32, 0xc0, 0x11,
	0x09, 0x64, 0x6e, 0x73, 0x2d, 0x61, 0x64, 0x6d,
	0x69, 0x6e, 0xc0, 0x11, 0x09, 0x48, 0x49, 0x9b,
	0x00, 0x00, 0x03, 0x84, 0x00, 0x00, 0x03, 0x84,
	0x00, 0x00, 0x07, 0x08, 0x00, 0x00, 0x00, 0x3c,
};

static void check_ns_msg(ns_msg_t *msg, int ecs)
{
	ns_qr_t *qr;
	ns_rr_t *rr;
	ns_soa_t *soa;

	assert(msg->id == 0x82);
	assert(msg->flags == 0x8180);
	assert(msg->qdcount == 1);
	assert(msg->ancount == 1);
	assert(msg->nscount == 1);
	if (ecs) {
		assert(msg->arcount == 1);
	}
	else {
		assert(msg->arcount == 0);
	}

	assert(msg->qrs != NULL);
	assert(msg->rrs != NULL);

	qr = msg->qrs;
	assert(strcmp(qr->qname, "ipv6.google.com.") == 0);
	assert(qr->qtype == NS_QTYPE_A);
	assert(qr->qclass == NS_QCLASS_IN);

	rr = msg->rrs;
	assert(strcmp(rr->name, "ipv6.google.com.") == 0);
	assert(rr->type == NS_QTYPE_CNAME);
	assert(rr->cls == NS_QCLASS_IN);
	assert(rr->ttl == 0x1516c);
	assert(strcmp(rr->rdata, "ipv6.l.google.com.") == 0);

	rr = msg->rrs + 1;
	assert(strcmp(rr->name, "l.google.com.") == 0);
	assert(rr->type == NS_QTYPE_SOA);
	assert(rr->cls == NS_QCLASS_IN);
	assert(rr->ttl == 0x28);
	soa = rr->rdata;
	assert(strcmp(soa->mname, "ns2.google.com.") == 0);
	assert(strcmp(soa->rname, "dns-admin.google.com.") == 0);
	assert(soa->serial == 0x948499b);
	assert(soa->refresh == 0x384);
	assert(soa->retry == 0x384);
	assert(soa->expire == 0x708);
	assert(soa->minimum == 0x3c);

	if (ecs) {
		ns_edns_t *edns;
		ns_opt_t *opt;
		uint8_t *optdata;
		rr = msg->rrs + 2;
		assert(strlen(rr->name) == 0);
		assert(rr->type == NS_TYPE_OPT);
		assert(rr->cls == NS_PAYLOAD_SIZE);
		assert(rr->ttl == 0);
		edns = rr->rdata;
		assert(edns != NULL);
		assert(edns->optcount == 1);
		assert(edns->opts != NULL);
		opt = edns->opts;
		assert(opt != NULL);
		assert(opt->code == NS_OPTCODE_ECS);
		assert(opt->length == 7);
		optdata = opt->data;
		assert(optdata != NULL);
		assert(optdata[0] == 0);
		assert(optdata[1] == ADDR_FAMILY_NUM_IP);
		assert(optdata[2] == 24);
		assert(optdata[3] == 0);
		assert(optdata[4] == 61);
		assert(optdata[5] == 135);
		assert(optdata[6] == 169 || optdata[6] == 170);
	}

}

static void test_parse_request()
{
	ns_msg_t msg;
	stream_t s = STREAM_INIT();
	int r;
	ns_rr_t *rr;
	struct sockaddr_storage addr;
	int mask;

	memset(&addr, 0, sizeof(struct sockaddr_storage));

    printf("test ns_msg parse ...  \n");

	printf("\nRAW ns_msg: \n");
	r = sizeof(ns_msg_bytes);
	bprint((char *)ns_msg_bytes, r);

	printf("\n");

	/*****************************************************************/

	r = init_ns_msg(&msg);
	assert(r == 0);

	r = ns_parse(&msg, ns_msg_bytes, sizeof(ns_msg_bytes));
	assert(r == 0);

	check_ns_msg(&msg, 0);

	ns_print(&msg);

	/*****************************************************************/

    printf("testing serialize ... \n");

	/*****************************************************************/

    printf("\nNO COMPRESSION: \n");
	stream_reset(&s);
    r = ns_serialize(&s, &msg, 0);
    assert(r > 0);
    assert(r >= 12);
	bprint(s.array, s.size);

	printf("\n");

	/* reparse */
	ns_msg_free(&msg);
	r = init_ns_msg(&msg);
	assert(r == 0);
	r = ns_parse(&msg, (uint8_t *)s.array, s.size);
	assert(r == 0);
	check_ns_msg(&msg, 0);

	/*****************************************************************/

	printf("\nWITH COMPRESSION: \n");
	stream_reset(&s);
	r = ns_serialize(&s, &msg, 1);
	assert(r > 0);
    assert(r >= 12);
	bprint(s.array, s.size);

    printf("\n");

	/* reparse */
	ns_msg_free(&msg);
	r = init_ns_msg(&msg);
	assert(r == 0);
	r = ns_parse(&msg, (uint8_t *)s.array, s.size);
	assert(r == 0);
	check_ns_msg(&msg, 0);

	/*****************************************************************/

    printf("\nWITH EDNS-CLIENT_SUBNET: \n");
	
	rr = ns_find_edns(&msg);
	assert(rr == NULL);

	rr = ns_add_edns(&msg);
	assert(rr != NULL);

	r = ns_ecs_parse_subnet((struct sockaddr *)&addr, &mask, "61.135.169.121/24");
	assert(r == 0);

	r = ns_edns_set_ecs(rr, (struct sockaddr *)&addr, mask, 0);
	assert(r == 0);

	stream_reset(&s);
	r = ns_serialize(&s, &msg, 0);
	assert(r > 0);
    assert(r >= 12);
	bprint(s.array, s.size);

    printf("\n");

	/* reparse */
	ns_msg_free(&msg);
	r = init_ns_msg(&msg);
	assert(r == 0);
	r = ns_parse(&msg, (uint8_t *)s.array, s.size);
	assert(r == 0);
	check_ns_msg(&msg, 1);

	/*****************************************************************/

	printf("\nWITH COMPRESSION AND EDNS-CLIENT_SUBNET: \n");

	rr = ns_find_edns(&msg);
	assert(rr != NULL);

	r = ns_ecs_parse_subnet((struct sockaddr *)&addr, &mask, "61.135.170.121/24");
	assert(r == 0);

	r = ns_edns_set_ecs(rr, (struct sockaddr *)&addr, mask, 0);
	assert(r == 0);

	stream_reset(&s);
	r = ns_serialize(&s, &msg, 1);
	assert(r > 0);
	assert(r >= 12);
	bprint(s.array, s.size);

	printf("\n");

	/* reparse */
	ns_msg_free(&msg);
	r = init_ns_msg(&msg);
	assert(r == 0);
	r = ns_parse(&msg, (uint8_t *)s.array, s.size);
	assert(r == 0);
	check_ns_msg(&msg, 1);

	/*****************************************************************/

	ns_msg_free(&msg);
	stream_free(&s);

    printf("pass\n");
}

static int test_rbtree_cb(rbtree_t *tree, rbnode_t *x, void *state)
{
	int *b = state;
	union {
        int iv;
        void *pv;
    } v;
    v.pv = x->info;
	assert(v.iv == x->key);
	assert(v.iv > 0 && v.iv < 101);
	b[x->key] = x->key;
	return 0;
}

static void test_rbtree()
{
	rbtree_t tree;
	rbnode_t *n;
	int r, i, b[101];
	rbnode_list_t *list;
	rbnode_list_item_t *item;
    union {
        int iv;
        void *pv;
    } convert;

    printf("test rbtree ...\n");

	r = rbtree_init(&tree);
	assert(r == 0);

    printf("insert 1~100 to rbtree ...\n");
	for (i = 0; i < 100; i++) {
        convert.iv = i + 1;
		n = rbtree_insert(&tree, i + 1, convert.pv);
		assert(n);
	}
    printf("finished\n");

	memset(b, 0, sizeof(b));

	rbtree_each(&tree, test_rbtree_cb, b);

    printf("check rbtree items ... \n");
	for (i = 1; i < 101; i++) {
		assert(b[i]);
	}
    printf("pass\n");

    printf("find item (key=33) ... \n");
	n = rbtree_lookup(&tree, 33);
	assert(n);
	assert(n->key == 33);
    printf("pass\n");

    printf("delete item (key=33) ... \n");
	rbtree_delete(&tree, n);

	memset(b, 0, sizeof(b));

	rbtree_each(&tree, test_rbtree_cb, b);

	for (i = 1; i < 101; i++) {
		if (i == 33) {
			assert(b[i] == 0);
		}
		else {
			assert(b[i]);
		}
	}
    printf("pass\n");

    printf("find items where between [50, 60] ... \n");
	list = rbtree_find(&tree, 50, 60);
	assert(list);
	assert(list->items);

	memset(b, 0, sizeof(b));

	item = list->items;
	while (item) {
		b[item->node->key] = item->node->key;
		item = item->next;
	}

	printf("\n");

	for (i = 1; i < 101; i++) {
		if (i >= 50 && i <= 60) {
			assert(b[i]);
		}
		else {
			assert(b[i] == 0);
		}
	}
    printf("pass\n");

	rbnode_list_destroy(list);

	rbtree_free(&tree);

    printf("rbtree test pass\n");
}

int main(int argc, char **argv)
{
	test_parse_request();

    printf("\n");
	test_rbtree();

    printf("\n");

	return EXIT_SUCCESS;
}

