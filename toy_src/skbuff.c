#include "syshead.h"
#include "skbuff.h"
#include "list.h"

struct sk_buff *
alloc_skb(unsigned int size)
{
	struct sk_buff *skb = malloc(sizeof(struct sk_buff));
	memset(skb, 0, sizeof(struct sk_buff));
	skb->data = malloc(size);    /* 记录下数据 */
	memset(skb->data, 0, size);

	skb->refcnt = 0;
	skb->head = skb->data;       /* 数据开始的地方 */
	skb->end = skb->data + size; /* 数据结束的地方 */
	list_init(&skb->list);
	return skb;
}

void 
free_skb(struct sk_buff *skb)
{
	if (skb->refcnt < 1) {
		free(skb->head);
		free(skb);
	}
}

/* skb_reserve丢弃掉前len个数据,或者说是保留前面长度为len的数据 */
void *
skb_reserve(struct sk_buff *skb, unsigned int len)
{
	skb->data += len;
	return skb->data;
}

uint8_t *
skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data -= len;  /* 这种数据填入的方式很有意思 */
	skb->len += len;
	return skb->data;  /* 返回数据的首地址 */
}

uint8_t *
skb_head(struct sk_buff *skb)
{
	return skb->head;		/* head指向数据的首部 */
}

void 
skb_reset_header(struct sk_buff* skb)
{
	skb->data = skb->end - skb->dlen;
	skb->len = skb->dlen;
}