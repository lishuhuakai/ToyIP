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

/* udp协议实际上并没有状态,这些只是为了处理方便而设定的伪状态 */
enum udp_state {
	UDP_UNCONNECTED,
	UDP_CONNECTED,
	UDP_CLOSED
};

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

#define udp_sk(sk) ((struct udp_sock*)sk)

#define UDP_HDR_LEN sizeof(struct udphdr)
#define UDP_DEFAULT_TTL 64
#define UDP_MAX_BUFSZ (0xffff - UDP_HDR_LEN)

static inline struct udphdr *
udp_hdr(const struct sk_buff *skb)
{
	return (struct udphdr *)(skb->head + ETH_HDR_LEN + IP_HDR_LEN);
}

/* 和TCP相比,UDP要简单很多,因为它没有状态 */
void udp_in(struct sk_buff *skb);
void udp_init(void);
struct sock * udp_alloc_sock();
struct sk_buff* udp_alloc_skb(int size);
int udp_sock_init(struct sock *sk);
int udp_write(struct sock *sk, const void *buf, const uint len);
int udp_read(struct sock *sk, void *buf, const uint len);
int udp_send(struct sock *sk, const void *buf, const uint len);
int udp_connect(struct sock *sk, const struct sockaddr_in *addr);
int udp_sendto(struct sock *sk, const void *buf, const uint size, const struct sockaddr_in *skaddr);
int udp_recvfrom(struct sock *sk, void *buf, const uint len, struct sockaddr_in *saddr);
int udp_close(struct sock *sk);
int udp_data_dequeue(struct udp_sock *usk, void *user_buf, const uint userlen, struct sockaddr_in *saddr);
uint16_t udp_generate_port();

struct sock * udp_lookup_sock(uint16_t dport);
int udp_checksum(struct sk_buff *skb, uint32_t saddr, uint32_t daddr);


#endif // !UDP_H
