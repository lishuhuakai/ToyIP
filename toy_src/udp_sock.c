#include "syshead.h"
#include "utils.h"
#include "ip.h"
#include "udp.h"

static int udp_sock_amount = 0;
static LIST_HEAD(sockets);
static pthread_rwlock_t slock = PTHREAD_RWLOCK_INITIALIZER;


struct sock *
	udp_lookup_sock(uint16_t port)
{

}


struct net_ops udp_ops = {
	.alloc_sock = &udp_alloc_sock,
	.init = &udp_sock_init,
	//.send = &udp_write,
	.connect = &udp_connect,
	//.sendto = &udp_sendto,
	//.recvfrom = &udp_recvfrom,
	//.read = &udp_read,
	.close = &udp_close,
};

void udp_init()
{
	
}


int
udp_close(struct sock *sk)
{
	/* udp本来就是一个没有状态的协议,不存在什么关闭不关闭. */
	return 0;
}

int
udp_sock_init(struct sock *sk)
{

	return 0;
}


int 
udp_sendto()
{

}

int
udp_recvfrom()
{

}

int
udp_connect(struct sock *sk, const struct sockaddr_in *addr)
{
	/* udp没有三次握手的过程,在这里只需要做一些检查,
	 如果没有错误,就记录对端的IP地址和端口号,立即返回. */
	extern char * stackaddr;

	// todo: 对ip地址做检查

	uint16_t dport = addr->sin_port;
	uint32_t daddr = addr->sin_addr.s_addr;
	sk->dport = ntohs(dport);
	sk->daddr = ntohl(daddr);
	sk->saddr = parse_ipv4_string(stackaddr);
	sk->sport = udp_generate_port();	/* 随机产生一个端口 */
	return 0;
}

int
udp_write(struct sock *sk, const void *buf, int len)
{
	// tofix:
	struct udp_sock *usk; // = udp_sock(sk);

	if (len < 0 || len > UDP_MAX_BUFSZ)
		return -1;
	/* 可以保证,调用udp_send时的数据长度在正常范围内.可以发送长度为0的udp数据报. */
	return udp_send(&usk->sk, buf, len);
}

static struct sk_buff *
udp_alloc_skb(int size)
{
	int reserved = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + size;
	struct sk_buff *skb = alloc_skb(reserved);
	skb->protocol = IP_UDP; 	/* udp协议 */
	skb->dlen = size;
	return skb;
}

int
udp_send(struct sock *usk, const void *buf, int len)
{
	struct sk_buff *skb;
	struct udphdr *udphd;
	int slen = len;

	// tofix: 可能需要将数据分片,如果数据过大的话,当然,这应该发生在ip层 
	skb = udp_alloc_skb(len);
	skb_push(skb, len);
	memcpy(skb->data, buf, len);
	udphd = udp_hdr(skb);

	udphd->sport = usk->sport;
	udphd->dport = usk->dport;
	udphd->len = skb->len;

	udpdbg("udpout");

	udphd->sport = htons(udphd->sport);
	udphd->dport = htons(udphd->dport);
	udphd->len = htons(udphd->len);
	udphd->csum = udp_checksum(skb, htonl(usk->saddr), htonl(usk->daddr));
	return ip_output(usk, skb);
}

struct sock *
	udp_alloc_sock()
{
	struct udp_sock *usk = malloc(sizeof(struct udp_sock));
	memset(usk, 0, sizeof(struct udp_sock));
	usk->sk.ops = &udp_ops;
	return &usk->sk;
}

static void
udp_process(struct sk_buff *skb, struct iphdr *iphd, struct udphdr *udphd)
{
	struct sock *sk;
	sk = udp_lookup_sock(udphd->dport);
	if (!sk) {			/* 如果没有找到对应的socket */
						// icmp_send();
		goto drop;
	}

	list_add_tail(&skb->list, &sk->receive_queue.head);	/* 放入接收队列 */
	sk->ops->recv_notify(sk);
	//free_sock(sk);
	return;
drop:
	free_skb(skb);
}

int
udp_read(struct sock *sk, void *buf, int len)
{
	/* udp可以读0个字节. */
	// tofix:
	struct udp_sock *usk; //udp_sk(sk);
	if (len < 0)
		return -1;
	return udp_receive(usk, buf, len);
}

int
udp_receive(struct udp_sock *usk, void *buf, int len)
{
	int rlen = 0;
	struct sock *sk = &usk->sk;
	struct socket *sock = sk->sock;
	memset(buf, 0, len);

	for (;;) {
		rlen = udp_data_dequeue(usk, buf, len);
		/* rlen != -1表示已经处理了一个udp数据报,可以返回了. */
		if (rlen != -1) break;

		/* 接下来rlen == -1,表示暂时没有udp数据可读取 */
		wait_sleep(&usk->sk.recv_wait);
	}
	return rlen;
}