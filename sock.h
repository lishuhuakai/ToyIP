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
	int(*connect)(struct sock *sk, const struct sockaddr *addr, int addr_len, int flags);
	int(*disconnect)(struct sock *sk, int flags);
	int(*write)(struct sock *sk, const void *buf, int len);
	int(*read)(struct sock *sk, void *buf, int len);
	int(*recv_notify)(struct sock *sk);
	int(*close)(struct sock *sk);
	int(*abort)(struct sock *sk);
};

/* sock
   需要说明一下的是,在处理过程中,sport,dport,sadddr以及daddr存储的都是主机字节序 */
struct sock {
	struct socket *sock;				// 
	struct net_ops *ops;				// 操纵网络的方法
	struct wait_lock recv_wait;
	struct sk_buff_head receive_queue;	// 接收队列
	struct sk_buff_head write_queue;	// 发送队列
	pthread_mutex_t lock;				// 多线程下需要加锁
	int protocol;						// 协议
	int state;
	int err;
	short int poll_events;				// 
	uint16_t sport;				
	uint16_t dport;						// 对方端口号
	uint32_t saddr;						// 源ip
	uint32_t daddr;						// 对端ip
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