#include "syshead.h"
#include "utils.h"
#include "ip.h"
#include "udp.h"
#include <sys/types.h>

static int udp_sock_amount = 0;
static LIST_HEAD(udp_socks);
static pthread_rwlock_t slock = PTHREAD_RWLOCK_INITIALIZER;

static void
udp_socks_enqueue(struct sock *sk)
{
	pthread_rwlock_wrlock(&slock);
	list_add_tail(&sk->link, &udp_socks);
	udp_sock_amount++;
	pthread_rwlock_unlock(&slock);
}

static void
udp_socks_remove(struct sock *sk)
{
	pthread_rwlock_wrlock(&slock);
	udp_sock_amount--;
	list_del_init(&sk->link);
	pthread_rwlock_unlock(&slock);
}

/**\
 * udp_sk_in_socks  判断sk是否已经挂到了udp_socks这张链表之中.
\**/
static inline int
udp_sk_in_socks(struct sock *sk)
{
	return sk->link.next == &sk->link;
}

struct sock *
	udp_lookup_sock(uint16_t dport)
{
	struct sock *sk;
	struct list_head *item;

	pthread_rwlock_rdlock(&slock);
	list_for_each(item, &udp_socks) {
		sk = list_entry(item, struct sock, link);
		if (sk->sport == dport) {
			pthread_rwlock_unlock(&slock);
			return sk;
		}
	}
	pthread_rwlock_unlock(&slock);
	return NULL;
}


static int udp_set_sport(struct sock *sk, uint16_t sport);
static int udp_recv_notify(struct sock *sk);
static int udp_bind(struct sock *sk, struct sockaddr_in *saddr);

struct net_ops udp_ops = {
	.alloc_sock = &udp_alloc_sock,
	.init = &udp_sock_init,
	.send_buf = &udp_write,
	.connect = &udp_connect,
	.sendto = &udp_sendto,
	.recvfrom = &udp_recvfrom,
	.recv_buf = &udp_read,
	.close = &udp_close,
	.bind = &udp_bind,
	.set_sport = &udp_set_sport,
	.recv_notify = &udp_recv_notify,
};

/**\
 * udp_init 整个udp协议如果有什么需要初始化的东西,可以放到这个函数中.
\**/
void 
udp_init()
{

}

static inline int
udp_recv_notify(struct sock *sk)
{
	if (&sk->recv_wait) {
		return wait_wakeup(&sk->recv_wait); /* 唤醒等待的进程 */
	}
	return -1;
}


int
udp_close(struct sock *sk)
{
	udp_socks_remove(sk);
	udp_free_sock(sk);
	return 0;
}

int
udp_sock_init(struct sock *sk)
{

	return 0;
}


/**\
 *	udp_recvfrom 用于捕获saddr地址传递过来的数据.
\**/
int
udp_recvfrom(struct sock *sk, void *buf, int len, struct sockaddr_in *saddr)
{
	int rlen;
	struct udp_sock *usk = udp_sk(sk);

	for (;;) {
		rlen = udp_data_dequeue(usk, buf, len, saddr);
		/* rlen != -1表示已经处理了一个udp数据报,可以返回了. */
		if (rlen != -1) break;

		/* 接下来rlen == -1,表示暂时没有udp数据可读取 */
		wait_sleep(&sk->recv_wait);
	}
	return rlen;
}


static int
udp_clean_up_receive_queue(struct sock *sk)
{
	struct sk_buff *skb;

	pthread_mutex_lock(&sk->receive_queue.lock);
	while ((skb = skb_peek(&sk->receive_queue)) != NULL) {
		/* 释放掉已经接收到了确认的数据 */
		skb_dequeue(&sk->receive_queue);
		skb->refcnt--;
		free_skb(skb);
	}
	pthread_mutex_unlock(&sk->receive_queue.lock);
	return 0;
}

int
udp_connect(struct sock *sk, const struct sockaddr_in *addr)
{
	extern char * stackaddr;
	int in_socks = 0;

	// todo: 对ip地址做检查

	uint16_t dport = addr->sin_port;
	uint32_t daddr = addr->sin_addr.s_addr;
	pthread_rwlock_wrlock(&slock);
	
	/* 可以多次调用connnect,第一要做的是断开之前的连接 */
	if (sk->state == UDP_CONNECTED)
		udp_clean_up_receive_queue(sk);

	/* 如果sk->saddr != NULL表示sk已经被挂在udp_sock之上了 */
	if (sk->saddr != NULL) in_socks = 1;


	sk->dport = ntohs(dport);
	sk->daddr = ntohl(daddr);
	sk->saddr = parse_ipv4_string(stackaddr);
	sk->sport = udp_generate_port();	/* 随机产生一个端口 */
	sk->state = UDP_CONNECTED;

	if (!in_socks) {
		list_add_tail(&sk->link, &udp_socks);
		udp_sock_amount++;
	}
	pthread_rwlock_unlock(&slock);
	return 0;
}

int
udp_write(struct sock *sk, const void *buf, int len)
{

	if (len < 0 || len > UDP_MAX_BUFSZ)
		return -1;
	/* 可以保证,调用udp_send时的数据长度在正常范围内.可以发送长度为0的udp数据报. */
	return udp_send(sk, buf, len);
}

struct sk_buff *
udp_alloc_skb(int size)
{
	int reserved = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + size;
	struct sk_buff *skb = alloc_skb(reserved);
	
	skb_reserve(skb, reserved);
	skb->protocol = IP_UDP; 	/* udp协议 */
	skb->dlen = size;
	return skb;
}


int 
udp_sendto(struct sock *sk, const void *buf, int size, const struct sockaddr_in *skaddr)
{
	extern char *stackaddr;
	int rc = -1;

	/* 如果已经调用过bind函数,绑定过地址了,那么skaddr必须为空 */
	if ((sk->state == UDP_CONNECTED) && (skaddr == NULL)) {
		rc = udp_send(sk, buf, size);	
	}
	/* 如果没有调用过bind函数,并且skaddr不为空 */
	else if ((sk->state == UDP_UNCONNECTED) && (skaddr != NULL)) {
		pthread_rwlock_wrlock(&slock);
		sk->daddr = ntohl(skaddr->sin_addr.s_addr);
		sk->dport = ntohs(skaddr->sin_port);
		sk->sport = udp_generate_port();	/* 随机产生一个端口 */
		sk->saddr = ip_parse(stackaddr);
		if (!udp_sk_in_socks(sk))
			list_add_tail(&sk->link, &udp_socks);
		pthread_rwlock_unlock(&slock);
		rc = udp_send(sk, buf, size);
	}
	return rc;
}

int
udp_send(struct sock *sk, const void *buf, int len)
{
	struct sk_buff *skb;
	struct udphdr *udphd;

	// tofix: 可能需要将数据分片,如果数据过大的话,当然,这应该发生在ip层 
	skb = udp_alloc_skb(len);
	skb_push(skb, len);
	memcpy(skb->data, buf, len);

	skb_push(skb, UDP_HDR_LEN);
	udphd = udp_hdr(skb);

	udphd->sport = sk->sport;
	udphd->dport = sk->dport;
	udphd->len = skb->len;

	udpdbg("udpout");

	udphd->sport = htons(udphd->sport);
	udphd->dport = htons(udphd->dport);
	udphd->len = htons(udphd->len);
	udphd->csum = udp_checksum(skb, htonl(sk->saddr), htonl(sk->daddr));
	return ip_output(sk, skb);
}

struct sock *
	udp_alloc_sock()
{
	struct udp_sock *usk = malloc(sizeof(struct udp_sock));
	memset(usk, 0, sizeof(struct udp_sock));
	usk->sk.ops = &udp_ops;
	usk->sk.state = UDP_UNCONNECTED;
	return &usk->sk;
}


void 
udp_free_sock(struct sock *sk)
{
	struct udp_sock *usk = udp_sk(sk);
	free(usk);
	sk = NULL;
}


int
udp_read(struct sock *sk, void *buf, int len)
{
	/* udp可以读0个字节. */
	struct udp_sock *usk = udp_sk(sk);
	int rlen = 0;
	if (len < 0) return -1;

	memset(buf, 0, len);

	for (;;) {
		rlen = udp_data_dequeue(usk, buf, len, NULL);
		/* rlen != -1表示已经处理了一个udp数据报,可以返回了. */
		if (rlen != -1) break;

		/* 接下来rlen == -1,表示暂时没有udp数据可读取 */
		wait_sleep(&sk->recv_wait);
	}
	return rlen;
}


static int
udp_port_used(uint16_t pt)
{
	struct sock *sk;
	struct list_head* item;
	list_for_each(item, &udp_socks) {
		sk = list_entry(item, struct sock, link);
		if (sk->sport == pt) {
			return 1;
		}
	}
	return 0;
}

static int
udp_set_sport(struct sock *sk, uint16_t sport)
{
	int rc = -1;
	if (!sport || udp_port_used(sport)) {
		goto out;
	}
	sk->sport = sport;
out:
	return rc;
}



/**\
 *  udp_bind 绑定到一个端口之上,这里需要注意一下,saddr在inet_bind函数中经历过检查
 *  并不存在什么问题.
\**/
static int 
udp_bind(struct sock *sk, struct sockaddr_in *saddr)
{
	int err;
	/* 不能多次调用bind */
	if (sk->saddr != 0) return -1;
	uint16_t bindport = ntohs(saddr->sin_port);
	if ((err = udp_set_sport(sk, bindport)) < 0) {
		/* 设定端口出错,可能是端口已经被占用 */
		return -1;
	}
	sk->saddr = ntohl(saddr->sin_addr.s_addr);
	/* 接下来需要将sk挂到udp_socks链上 */
	udp_socks_enqueue(sk);
	return 0;
}
