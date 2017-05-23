#ifndef SKBUFF_H
#define SKBUFF_H

#include "netdev.h"
#include "route.h"
#include "list.h"
#include <inttypes.h>
#include <pthread.h>
#include <bits/pthreadtypes.h>

struct sk_buff {
	struct list_head list;
	struct rtentry *rt;
	struct netdev *dev;
	int refcnt;				/* 引用计数 */
	uint16_t protocol;
	uint32_t len;			/* len主要记录已经填入的数据的大小,仅供输出使用 */
	uint32_t dlen;			/* 数据的大小,不包含头部(以太网,ip,tcp头部) */
	uint32_t seq;
	uint32_t end_seq;
	uint8_t *end;
	uint8_t *head;
	uint8_t *data;
	uint8_t *payload;
};

struct sk_buff_head {
	struct list_head head;
	uint32_t qlen;				/* 记录链表的长度 */
	pthread_mutex_t lock;		/* 锁,避免争用 */
};

struct sk_buff *alloc_skb(unsigned int size);
void free_skb(struct sk_buff *skb);
uint8_t *skb_push(struct sk_buff *skb, unsigned int len);
uint8_t *skb_head(struct sk_buff *skb);
void *skb_reserve(struct sk_buff *skb, unsigned int len);
void skb_reset_header(struct sk_buff *skb);

static inline uint32_t 
skb_queue_len(const struct sk_buff_head *list)
{
	return list->qlen;
}

static inline void 
skb_queue_init(struct sk_buff_head *list)
{
	list_init(&list->head);
	list->qlen = 0;
	pthread_mutex_init(&list->lock, NULL);
}

static inline void
skb_queue_add(struct sk_buff_head *list, struct sk_buff *new_item, struct sk_buff *next)
{
	list_add(&new_item->list, &next->list);
	list->qlen += 1;
}

/* skb_queue_tail 将skb添加到list的尾部 */
static inline void
skb_queue_tail(struct sk_buff_head *list, struct sk_buff *new_item)
{
	list_add_tail(&new_item->list, &list->head);
	list->qlen += 1;
}

/* skb_dequeue 用于丢弃队列的首项 */
static inline struct sk_buff *
skb_dequeue(struct sk_buff_head *list)
{
	struct sk_buff *skb = list_first_entry(&list->head, struct sk_buff, list);
	list_del(&skb->list);
	list->qlen -= 1;
	return skb;
}

static inline int 
skb_queue_empty(const struct sk_buff_head *list)
{
	return skb_queue_len(list) < 1;
}

static inline struct sk_buff*
skb_peek(struct sk_buff_head *list)
{
	if (skb_queue_empty(list)) return NULL;
	return list_first_entry(&list->head, struct sk_buff, list);
}

static inline void
skb_queue_free(struct sk_buff_head *list)
{
	struct sk_buff *skb = NULL;
	while ((skb = skb_peek(list)) != NULL) {
		skb_dequeue(list);
		skb->refcnt--;
		free_skb(skb);
	}
}

#endif // !SKBUFF_H