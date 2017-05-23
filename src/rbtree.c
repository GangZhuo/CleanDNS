#include <stdio.h>
#include <stdlib.h>
#include "rbtree.h"

static rbnode_t s_rbtree_nil = {
	.key = 0,
	.info = NULL,
	.red = 0,
	.left = &s_rbtree_nil,
	.right = &s_rbtree_nil,
	.parent = &s_rbtree_nil,
};

rbnode_t *nil = &s_rbtree_nil;

int rbtree_init(rbtree_t *tree)
{
	rbnode_t* root = &tree->root;

	root->parent = root->left = root->right = nil;
	root->key = 0;
	root->red = 0;

	return 0;
}

static void rbtree_free_node(rbtree_t *tree, rbnode_t *x) {
	if (x != nil) {
		rbtree_free_node(tree, x->left);
		rbtree_free_node(tree, x->right);
		free(x);
	}
}

void rbtree_free(rbtree_t *tree)
{
	if (tree)
	{
		rbtree_free_node(tree, tree->root.left);
	}
}

/* binary tree insert */
static void btree_insert(rbtree_t *tree, rbnode_t *z) {
	rbnode_t *x, *y;
	z->left = z->right = nil;
	y = &tree->root;
	x = tree->root.left;
	while (x != nil) {
		y = x;
		if (z->key < x->key) {
			x = x->left;
		}
		else {
			x = x->right;
		}
	}
	z->parent = y;
	if (y == &tree->root || z->key < y->key) {
		y->left = z;
	}
	else {
		y->right = z;
	}
}

void rbtree_left_rotate(rbtree_t *tree, rbnode_t *x) {
	rbnode_t *y;

	y = x->right;
	x->right = y->left;

	if (y->left != nil)
		y->left->parent = x;

	y->parent = x->parent;

	if (x == x->parent->left) {
		x->parent->left = y;
	}
	else {
		x->parent->right = y;
	}

	y->left = x;
	x->parent = y;
}

void rbtree_right_rotate(rbtree_t *tree, rbnode_t *y) {
	rbnode_t *x;

	x = y->left;
	y->left = x->right;

	if (nil != x->right)
		x->right->parent = y;

	x->parent = y->parent;
	if (y == y->parent->left) {
		y->parent->left = x;
	}
	else {
		y->parent->right = x;
	}
	x->right = y;
	y->parent = x;
}

static void rbtree_fixup(rbtree_t *tree, rbnode_t *z)
{
	rbnode_t *x, *y;
	x = z;
	x->red = 1;
	while (x->parent->red) {
		if (x->parent == x->parent->parent->left) {
			y = x->parent->parent->right;
			if (y->red) {
				x->parent->red = 0;
				y->red = 0;
				x->parent->parent->red = 1;
				x = x->parent->parent;
			}
			else {
				if (x == x->parent->right) {
					x = x->parent;
					rbtree_left_rotate(tree, x);
				}
				x->parent->red = 0;
				x->parent->parent->red = 1;
				rbtree_right_rotate(tree, x->parent->parent);
			}
		}
		else {
			y = x->parent->parent->left;
			if (y->red) {
				x->parent->red = 0;
				y->red = 0;
				x->parent->parent->red = 1;
				x = x->parent->parent;
			}
			else {
				if (x == x->parent->left) {
					x = x->parent;
					rbtree_right_rotate(tree, x);
				}
				x->parent->red = 0;
				x->parent->parent->red = 1;
				rbtree_left_rotate(tree, x->parent->parent);
			}
		}
	}
	tree->root.left->red = 0;
}

rbnode_t *rbtree_insert(rbtree_t *tree, int key, void *info)
{
	rbnode_t *z;

	z = (rbnode_t*)malloc(sizeof(rbnode_t));
	if (z == NULL)
		return NULL;

	z->key = key;
	z->info = info;

	btree_insert(tree, z);

	rbtree_fixup(tree, z);

	return z;
}

rbnode_t *rbtree_lookup(rbtree_t *tree, int key) {
	rbnode_t *x = tree->root.left;
	if (x == nil)
		return NULL;
	while (x->key != key) {
		if (x->key > key) {
			x = x->left;
		}
		else {
			x = x->right;
		}
		if (x == nil)
			return NULL;
	}

	return x;
}

static rbnode_t *rbtree_successor(rbtree_t *tree, rbnode_t *x) {
	rbnode_t *y, *root = &tree->root;

	if (nil != (y = x->right)) {
		while (y->left != nil) {
			y = y->left;
		}
		return y;
	}
	else {
		y = x->parent;
		while (x == y->right) {
			x = y;
			y = y->parent;
		}
		if (y == root) return nil;
		return y;
	}
}

static void rbtree_delete_fixup(rbtree_t *tree, rbnode_t *x) {
	rbnode_t *root = tree->root.left, *w;

	while ((!x->red) && (root != x)) {
		if (x == x->parent->left) {
			w = x->parent->right;
			if (w->red) {
				w->red = 0;
				x->parent->red = 1;
				rbtree_left_rotate(tree, x->parent);
				w = x->parent->right;
			}
			if ((!w->right->red) && (!w->left->red)) {
				w->red = 1;
				x = x->parent;
			}
			else {
				if (!w->right->red) {
					w->left->red = 0;
					w->red = 1;
					rbtree_right_rotate(tree, w);
					w = x->parent->right;
				}
				w->red = x->parent->red;
				x->parent->red = 0;
				w->right->red = 0;
				rbtree_left_rotate(tree, x->parent);
				x = root;
			}
		}
		else {
			w = x->parent->left;
			if (w->red) {
				w->red = 0;
				x->parent->red = 1;
				rbtree_right_rotate(tree, x->parent);
				w = x->parent->left;
			}
			if ((!w->right->red) && (!w->left->red)) {
				w->red = 1;
				x = x->parent;
			}
			else {
				if (!w->left->red) {
					w->right->red = 0;
					w->red = 1;
					rbtree_left_rotate(tree, w);
					w = x->parent->left;
				}
				w->red = x->parent->red;
				x->parent->red = 0;
				w->left->red = 0;
				rbtree_right_rotate(tree, x->parent);
				x = root;
			}
		}
	}
	x->red = 0;
}

void *rbtree_delete(rbtree_t *tree, rbnode_t *z)
{
	rbnode_t *x, *y, *root = &tree->root;
	void *info = NULL;

	y = ((z->left == nil) || (z->right == nil)) ? z : rbtree_successor(tree, z);
	x = (y->left == nil) ? y->right : y->left;
	if (root == (x->parent = y->parent)) {
		root->left = x;
	}
	else {
		if (y == y->parent->left) {
			y->parent->left = x;
		}
		else {
			y->parent->right = x;
		}
	}
	if (y != z) {
		if (!(y->red))
			rbtree_delete_fixup(tree, x);

		y->left = z->left;
		y->right = z->right;
		y->parent = z->parent;
		y->red = z->red;
		z->left->parent = z->right->parent = y;
		if (z == z->parent->left) {
			z->parent->left = y;
		}
		else {
			z->parent->right = y;
		}
		info = z->info;
		free(z);
	}
	else {
		if (!(y->red))
			rbtree_delete_fixup(tree, x);
		info = y->info;
		free(y);
	}
	return info;
}

void rbtree_each_node(rbtree_t *tree, rbnode_t *x,
	int (*cb)(rbtree_t *tree, rbnode_t *x, void *state), void *state)
{
	rbnode_t *root = &tree->root;
	if (x != nil) {
		if (cb(tree, x, state))
			return;
		rbtree_each_node(tree, x->left, cb, state);
		rbtree_each_node(tree, x->right, cb, state);
	}
}

void rbtree_each(rbtree_t *tree,
	int (*cb)(rbtree_t *tree, rbnode_t *x, void *state), void *state)
{
	rbtree_each_node(tree, tree->root.left, cb, state);
}

static rbnode_t *rbtree_predecessor(rbtree_t *tree, rbnode_t *x) {
	rbnode_t *y, *root = &tree->root;

	if (nil != (y = x->left)) {
		while (y->right != nil) {
			y = y->right;
		}
		return y;
	}
	else {
		y = x->parent;
		while (x == y->left) {
			if (y == root) return nil;
			x = y;
			y = y->parent;
		}
		return y;
	}
}

rbnode_list_t *rbnode_list_create()
{
	rbnode_list_t *list;
	list = malloc(sizeof(rbnode_list_t));
	if (list == NULL)
		return NULL;
	list->items = NULL;
	return list;
}

void rbnode_list_destroy(rbnode_list_t *list)
{
	rbnode_list_item_t *item, *temp;

	if (list) {
		item = list->items;
		while (item) {
			temp = item;
			item = item->next;
			free(temp);
		}
		free(list);
	}
}

int rbnode_list_add(rbnode_list_t *list, rbnode_t *h)
{
	rbnode_list_item_t *item;
	item = malloc(sizeof(rbnode_list_item_t));
	if (item == NULL) {
		return -1;
	}

	item->node = h;
	if (list->items) {
		item->next = list->items;
		list->items = item;
	}
	else {
		list->items = item;
		item->next = NULL;
	}

	return 0;
}

rbnode_list_t *rbtree_find(rbtree_t *tree, int low, int high)
{
	rbnode_list_t *list;
	rbnode_t *x, *h = nil;

	list = rbnode_list_create();
	if (list == NULL)
		return NULL;

	x = tree->root.left;
	while (x != nil) {
		if (x->key > high) {
			x = x->left;
		}
		else {
			h = x;
			x = x->right;
		}
	}

	while (h != nil && h->key >= low) {
		if (rbnode_list_add(list, h) != 0) {
			rbnode_list_destroy(list);
			return NULL;
		}
		h = rbtree_predecessor(tree, h);
	}

	return list;
}
