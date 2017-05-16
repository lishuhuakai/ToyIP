#ifndef SOCK_H
#define SOCK_H

#include "socket.h"
#include "wait.h"
#include "skbuff.h"
#include <bits/pthreadtypes.h>

struct sock;

/* net_pos 相当于接口,封装了一组操作网络的方法 */
struct net_ops {
	struct sock* (*alloc_sock)(int protocol);
	int(*init)(struct sock *sk);
	int(*connect)(struct sock *sk, const struct sockaddr_in *addr);
	int(*send_buf)(struct sock *sk, const void *buf, int len);  
	int(*send_pkg)(struct sock *sk,struct sk_buff *skb);  /* for udp sendto function */
	int(*recv_buf)(struct sock *sk, void *buf, int len);
	int(*recv_pkg)(struct sock *sk, void *buf, int len);  /* for udp recvfrom function */
	int(*bind)(struct sock *, struct sockaddr_in *);
	int(*recv_notify)(struct sock *sk);
	int(*close)(struct sock *sk);				
	int(*listen)(struct sock *, int);			/* for tcp */
	struct sock * (*accept)(struct sock *);		/* for tcp */
	int(*set_sport)(struct sock *, uint16_t port);
};

/* sock
   需要说明一下的是,在处理过程中,sport,dport,sadddr以及daddr存储的都是主机字节序 */
struct sock {
	struct list_head link;				/* link域方便将sock拉成一张链表 */
	struct socket *sock;				/* socket和sock是相互包含的,更确切的说,是一体两面 */ 
	struct net_ops *ops;				/* 操纵网络的方法 */
	struct wait_lock recv_wait;
	struct sk_buff_head receive_queue;	/* 接收队列  */
	struct sk_buff_head write_queue;	/* 发送队列  */
 	pthread_mutex_t lock;				/* 多线程下需要加锁 */
	int protocol;						/* 协议 */
	int state;							/* 状态这个东西应该是tcp协议所独有 */
	int err;
	short int poll_events;			
	uint16_t sport;				
	uint16_t dport;						/* 对方端口号 */
	uint32_t saddr;						/* 源ip */
	uint32_t daddr;						/* 对端ip */
};

static inline struct sk_buff*
write_queue_head(struct sock *sk) {
	return skb_peek(&sk->write_queue);
}

struct sock *sk_alloc(struct net_ops *ops, int protocol);
void sock_free(struct sock *sk);
void sock_init_data(struct socket *sock, struct sock *sk);
void sock_connected(struct sock *sk);

#endif // !SOCK_H