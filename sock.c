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
sock_init_data(struct socket *sock, struct sock *sk)
{
	sock->sk = sk;
	sk->sock = sock;

	wait_init(&sk->recv_wait);
	skb_queue_init(&sk->receive_queue);		/* 初始化接收队列 */
	skb_queue_init(&sk->write_queue);		/* 初始化发送队列 */
	pthread_mutex_init(&sk->lock, NULL);	/* 初始化锁 */

	sk->poll_events = 0;
	sk->ops->init(sk);
}

void 
sock_free(struct sock *sk)
{
	skb_queue_free(&sk->receive_queue);
	skb_queue_free(&sk->write_queue);
	pthread_mutex_destroy(&sk->lock);
}

void
sock_connected(struct sock *sk)
{
	struct socket *sock = sk->sock;

	sock->state = SS_CONNECTED;		/* 连接成功 */
	sk->err = 0;
	sk->poll_events = POLLOUT;		/* 关注可读事件 */

	wait_wakeup(&sock->sleep);		/* 当有数据可读的时候,唤醒 */
}