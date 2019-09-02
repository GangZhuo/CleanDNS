#ifndef CLEANDNS_DLLIST_H_
#define CLEANDNS_DLLIST_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dlitem_t dlitem_t;
typedef struct dllist_t dllist_t;

struct dlitem_t {
	dlitem_t  *next;
	dlitem_t  *prev;
};

struct dllist_t {
	dlitem_t  head;
};

#define DLLIST_INIT(list)  { { &(list).head, &(list).head } }

#define dllist_init(list) \
    do { \
        (list)->head.next = &(list)->head; \
        (list)->head.prev = &(list)->head; \
    } while (0)

#define dllist_foreach_void(list, curr, _next) \
    for ((curr) = dllist_start((list)), (_next) = (curr)->next; \
         !dllist_is_end((list), (curr)); \
         (curr) = (_next), (_next) = (curr)->next)

#define dllist_foreach(list, curr, _next, etype, element, item_field) \
    for ((curr) = dllist_start((list)), (_next) = (curr)->next, \
         (element) = dllist_container_of((curr), etype, item_field); \
         !dllist_is_end((list), (curr)); \
         (curr) = (_next), (_next) = (curr)->next, \
         (element) = dllist_container_of((curr), etype, item_field))

#define dllist_add_after(pred, element) \
    do { \
        (element)->prev = (pred); \
        (element)->next = (pred)->next; \
        (pred)->next->prev = (element); \
        (pred)->next = (element); \
    } while (0)

#define dllist_add_before(succ, element) \
    do { \
        (element)->next = (succ); \
        (element)->prev = (succ)->prev; \
        (succ)->prev->next = (element); \
        (succ)->prev = (element); \
    } while (0)

#define dllist_add_to_head(list, element) \
    dllist_add_after(&(list)->head, (element))

#define dllist_add_to_tail(list, element) \
    dllist_add_before(&(list)->head, (element))

#define dllist_add  dllist_add_to_tail


#define dllist_add_list_to_head(dest, src) \
    do { \
        dlitem_t *dest_start = dllist_start(dest); \
        dlitem_t *src_start = dllist_start(src); \
        dest_start->prev = &(src)->head; \
        src_start->prev = &(dest)->head; \
        (src)->head.next = dest_start; \
        (dest)->head.next = src_start; \
        dllist_remove(&(src)->head); \
        dllist_init(src); \
    } while (0)

#define dllist_add_list_to_tail(dest, src) \
    do { \
        dlitem_t *dest_end = dllist_end(dest); \
        dlitem_t *src_end = dllist_end(src); \
        dest_end->next = &(src)->head; \
        src_end->next = &(dest)->head; \
        (src)->head.prev = dest_end; \
        (dest)->head.prev = src_end; \
        dllist_remove(&(src)->head); \
        dllist_init(src); \
    } while (0)


#define dllist_remove(element) \
    do { \
        (element)->prev->next = (element)->next; \
        (element)->next->prev = (element)->prev; \
    } while (0)

#define dllist_init_remove(element) \
    do { \
        dllist_remove(element); \
        (element)->prev = NULL; \
        (element)->next = NULL; \
    } while (0)


#define dllist_is_empty(list) \
    (dllist_is_end((list), dllist_start((list))))


#define dllist_head(list) \
    (((list)->head.next == &(list)->head)? NULL: (list)->head.next)
#define dllist_tail(list) \
    (((list)->head.prev == &(list)->head)? NULL: (list)->head.prev)

#define dllist_start(list) \
    ((list)->head.next)
#define dllist_end(list) \
    ((list)->head.prev)

#define dllist_is_start(list, element) \
    ((element) == &(list)->head)
#define dllist_is_end(list, element) \
    ((element) == &(list)->head)

#define dllist_offsetof(s,m) ((size_t)&(((s*)0)->m))

#define dllist_container_of(field, struct_type, field_name) \
    ((struct_type *) (((char *)(field)) - dllist_offsetof(struct_type, field_name)))


#ifdef __cplusplus
}
#endif

#endif
