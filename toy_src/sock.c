#include "syshead.h"
#include "sock.h"
#include "socket.h"

struct sock *
sk_alloc(struct net_ops *ops, int protocol) 
{
	struct sock *sk;
	sk = ops->alloc_sock(protocol);
	sk->ops = ops;	/* 记录下一套操作方法 */
	return sk;
}

void
sk_init(struct sock *sk)
{
	sk->sock = NULL;
	wait_init(&sk->recv_wait);
	skb_queue_init(&sk->receive_queue);		/* 初始化接收队列 */
	skb_queue_init(&sk->write_queue);		/* 初始化发送队列 */
	pthread_mutex_init(&sk->lock, NULL);	/* 初始化锁 */
	sk->ops->init(sk);						/* net_ops做初始化工作 */
}

/* sk_init_with_socket用于初始化sk,并且将sk记录到sock中 */
void
sk_init_with_socket(struct socket *sock, struct sock *sk)
{
	sk_init(sk);
	sock->sk = sk;
	sk->sock = sock;
}

void 
sk_free(struct sock *sk)
{
	skb_queue_free(&sk->receive_queue);
	skb_queue_free(&sk->write_queue);
	pthread_mutex_destroy(&sk->lock);
}