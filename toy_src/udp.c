#include "udp.h"

/**\
 * udp_genarate_port 随机产生udp接口.tcp和udp的接口系统是独立的. 
\**/
uint16_t 
udp_generate_port()
{
	// todo: 更好的方法来产生port
	static int port = 40000;
	return ++port + (timer_get_tick() % 10000);
}


int
udp_checksum(struct sk_buff *skb, uint32_t saddr, uint32_t daddr)
{
	return tcp_udp_checksum(saddr, daddr, IP_UDP, skb->data, skb->len);
}



static void
udp_init_segment(struct udphdr *udphd, struct iphdr *iphd, struct sk_buff *skb)
{
	udphd->sport = htons(udphd->sport);
	udphd->dport = htons(udphd->dport);
	udphd->len = htons(udphd->len);
	udphd->csum = htons(udphd->csum);
	skb->payload = udphd->data;

	skb->dlen = udphd->len - UDP_HDR_LEN;
}

void
udp_in(struct sk_buff *skb)
{
	struct iphdr *iphd = ip_hdr(skb);	/* ip头部 */
	struct udphdr *udphd = udp_hdr(skb);
	struct sock *sk;

	udp_init_segment(udphd, iphd, skb);
	// todo: 检查校验值

	sk = udp_lookup_sock(udphd->dport);

	if (!sk) {
		// tofix: 发送icmp不可达回应.
		goto drop;
	}
	/* 直接将数据加入到接收队列的尾部即可. */
	skb_queue_tail(&sk->receive_queue, skb);
	sk->ops->recv_notify(sk);
	return;
drop:
	free_skb(skb);
}



/**\
 * udp_data_dequeue 取出一个数据报.
\**/
int
udp_data_dequeue(struct udp_sock *usk, void *user_buf, int userlen, struct sockaddr_in *saddr)
{
	struct sock *sk = &usk->sk;
	struct udphdr *udphd;
	struct iphdr *ih;
	struct sk_buff *skb;
	int rlen = -1;
	/* udp可不是什么流式协议,而且,有一点需要注意,一旦userlen比实际的udp数据包长度要小,
	  那么多的部分会被丢弃掉. */
	pthread_mutex_lock(&sk->receive_queue.lock);
	if (!skb_queue_empty(&sk->receive_queue))
	{
		skb = skb_peek(&sk->receive_queue);
		udphd = udp_hdr(skb);
		ih = ip_hdr(skb);
		rlen = skb->dlen > userlen? userlen : skb->dlen;
		memcpy(user_buf, skb->payload, rlen);
		/* 即使该数据报的数据没有读完,也要丢弃掉. */
		skb_dequeue(&sk->receive_queue);
		if (saddr) {
			saddr->sin_family = AF_INET;
			saddr->sin_port = htons(udphd->sport);
			saddr->sin_addr.s_addr = htonl(ih->saddr);
		}
		skb->refcnt--;
		free_skb(skb);
	}
	pthread_mutex_unlock(&sk->receive_queue.lock);
	return rlen;
}

/**\ 
 * udp_data_enqueue 当udp数据到来时,将数据报放到接收队列尾部. 
\**/
int
udp_data_enqueue(struct udp_sock *usk, struct udphdr *udphd, struct sk_buff *skb)
{
	struct sock *sk = &usk->sk;
	skb_queue_tail(&sk->receive_queue, skb);
	return 0;
}






