#ifndef UDP_H
#define UDP_H

#include "ip.h"
#include "ethernet.h"
#include "sock.h"
#include "skbuff.h"
#include "timer.h"
#include "utils.h"


#ifdef DEBUG_UDP
#define udpdbg(x)

#else
#define udpdbg(x)
#endif

struct udphdr {
	uint16_t sport;		/* 源端口				*/
	uint16_t dport;		/* 目的端口			*/
	uint16_t len;		/* 长度,包括首部和数据 */
	uint16_t csum;		/* 检验和				*/
	uint8_t data[];
} __attribute__((packed));

struct udp_sock {
	struct sock sk;
};

#define UDP_HDR_LEN sizeof(struct udphdr)
#define UDP_DEFAULT_TTL 64
#define UDP_MAX_BUFSZ (0xffff - UDP_HDR_LEN)

static inline struct udphdr *
udp_hdr(const struct sk_buff *skb)
{
	return (struct udphdr *)(skb->head + ETH_HDR_LEN + IP_HDR_LEN);
}

/* 和TCP相比,UDP要简单很多,因为它没有状态 */
struct sock *udp_lookup_sock(uint16_t port);
void udp_in(struct sk_buff *skb);
void udp_init(void);
struct sock * udp_alloc_sock();
int udp_init_sock(struct sock *sk);
int udp_write(struct sock *sk, const void *buf, int len);
int udp_read(struct sock *sk, void *buf, int len);
int udp_send(struct sock *usk, const void *buf, int len);
int udp_connect(struct sock *sk, const struct sockaddr_in *addr);
int udp_close(struct sock *sk);
int udp_receive(struct udp_sock *usk, void *buf, int len);
int udp_data_dequeue(struct udp_sock *usk, void *user_buf, int userlen);

int
udp_checksum(struct sk_buff *skb, uint32_t saddr, uint32_t daddr);

#endif // !UDP_H