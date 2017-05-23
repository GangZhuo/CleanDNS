#ifndef CLEANDNS_RBTREE_H_
#define CLEANDNS_RBTREE_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rbnode_t {
	int key;
	void *info;
	int red;
	struct rbnode_t* left;
	struct rbnode_t* right;
	struct rbnode_t* parent;
} rbnode_t;

typedef struct rbtree_t {
	rbnode_t root;
} rbtree_t;

typedef struct rbnode_list_item_t {
	rbnode_t *node;
	struct rbnode_list_item_t *next;
} rbnode_list_item_t;

typedef struct rbnode_list_t {
	rbnode_list_item_t *items;
} rbnode_list_t;

extern rbnode_t *nil;

int rbtree_init(rbtree_t *tree);

void rbtree_free(rbtree_t *tree);

rbnode_t *rbtree_insert(rbtree_t *tree, int key, void *info);

rbnode_t *rbtree_lookup(rbtree_t *tree, int key);

void *rbtree_delete(rbtree_t *tree, rbnode_t *node);

/* Interrupted when 'cb' return non-zero value */
void rbtree_each(rbtree_t *tree,
	int(*cb)(rbtree_t *tree, rbnode_t *x, void *state), void *state);

/* find nodes between [low, high]: key >= low and key <= high */
rbnode_list_t *rbtree_find(rbtree_t *tree, int low, int high);

rbnode_list_t *rbnode_list_create();

void rbnode_list_destroy(rbnode_list_t *list);

int rbnode_list_add(rbnode_list_t *list, rbnode_t *h);

#define rbtree_delete_bykey(tree, key) \
    do { \
        rbnode_t *n = rbtree_lookup((tree), (key)); \
        if (n != NULL) { \
            rbtree_delete((tree), n); \
        } \
    } while(0)

#ifdef __cplusplus
}
#endif

#endif /*CLEANDNS_RBTREE_H_*/
