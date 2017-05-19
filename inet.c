#include "syshead.h"
#include "inet.h"
#include "socket.h"
#include "sock.h"
#include "tcp.h"
#include "wait.h"
#include "netdev.h"

//
// inet 更多指的是tcp socket.
// 
extern struct net_ops tcp_ops;
extern struct net_ops udp_ops;


static int INET_OPS = 2;

struct net_family inet = {
	.create = inet_create,
};

static struct sock_ops sock_ops = {
	.connect = &inet_connect,
	.write = &inet_write,
	.bind = &inet_bind,
	.read = &inet_read,
	.listen = &inet_listen,
	.close = &inet_close,
	.free = &inet_free,
	.accept = &inet_accept,
};

static struct sock_type inet_ops[] = {
	{ 
	  .sock_ops = &sock_ops, .net_ops = &tcp_ops,
	  .type = SOCK_STREAM, .protocol = IPPROTO_TCP,
	},
	{
	  .sock_ops = &sock_ops,.net_ops = &udp_ops,
	  .type = SOCK_DGRAM, .protocol = IPPROTO_UDP,
	}
};

/* inet_create主要用于给struct socket *sock构建和初始化struct sock *sk. */
int
inet_create(struct socket *sock, int protocol) 
{
	struct sock *sk;
	struct sock_type *skt = NULL;
	/* 这里只支持udp或者tcp */
	for (int i = 0; i < INET_OPS; i++) {
		if (inet_ops[i].type & sock->type) {
			skt = &inet_ops[i];
			break;
		}
	}

	if (!skt) {
		print_err("Could not find socktype for socket\n");
		return 1;
	}

	sock->ops = skt->sock_ops;	/* 记录下对struct socket的操纵方法,在这个协议栈内,
								sock->ops == &sock_ops始终成立 */
	sk = sk_alloc(skt->net_ops, protocol);	/* 构建sock */
	
	
	sk->protocol = protocol;

	sock_init_data(sock, sk);	/* 对sock的其他域做一些初始化工作. */
	return 0;
}

int
inet_socket(struct socket *sock, int protocol)
{
	return 0;
}

int
inet_connect(struct socket *sock, const struct sockaddr_in *addr)
{ 
	struct sock *sk = sock->sk;
	int rc = -1;
	/* 不允许多次连接 */
	if (sk->sport) goto out;
	if (sk->ops->connect)
		rc = sk->ops->connect(sk, addr);
out:
	return rc;
}

/*
 * 接下来的inet_write, inet_read等函数直接调用sock的write, read函数.
 */

int
inet_write(struct socket *sock, const void *buf, int len)
{
	struct sock *sk = sock->sk;
	return sk->ops->send_buf(sk, buf, len);
}

int
inet_read(struct socket *sock, void *buf, int len)
{
	struct sock *sk = sock->sk;
	return sk->ops->recv_buf(sk, buf, len);
}

int
inet_close(struct socket *sock)
{
	struct sock *sk = sock->sk;
	int err = 0;

	pthread_mutex_lock(&sk->lock);
	if (sock->sk->ops->close(sk) != 0) {	/* 首先关闭连接 */
		print_err("Error on sock op close\n");
	}

	err = sk->err;
	pthread_mutex_unlock(&sk->lock);
	return err;
}

int
inet_free(struct socket *sock)
{
	struct sock *sk = sock->sk;
	sock_free(sk);
	free(sock->sk);
	return 0;
}

int
inet_bind(struct socket *sock, struct sockaddr_in * skaddr)
{
	struct sock *sk = sock->sk;	/* struct sock表示一个连接 */
	int err = -1;
	uint32_t bindaddr;
	uint16_t bindport;

	if (sk->ops->bind)
		return sk->ops->bind(sock->sk, skaddr);

	if (sk->sport) goto err_out;
	/* 接下来需要检查skadddr中的地址是不是本机地址 */
	bindaddr = ntohl(skaddr->sin_addr.s_addr);
	bindport = ntohs(skaddr->sin_port);
	if (!local_ipaddress(bindaddr)) goto err_out;
	sk->saddr = bindaddr;

	if (sk->ops->set_sport) {
		if (err = sk->ops->set_sport(sk, bindport) < 0)	{	
			/* 设定端口出错,可能是端口已经被占用 */
			sk->saddr = 0;
			goto err_out;
		}
	}
	else {
		sk->sport = bindport;
	}
	/* 绑定成功 */
	err = 0;
	sk->dport = 0;
	sk->daddr = 0;
err_out:
	return err;
}

int
inet_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	int err = -1;

	if (sock->type != SOCK_STREAM)
		return -1;

	err = sk->ops->listen(sk, backlog);
	return err;
}

/* inet_accept函数用于监听对端发送过来的连接 */
int
inet_accept(struct socket *sock, struct socket *newsock, 
	struct sockaddr_in* skaddr)
{
	struct sock *sk = sock->sk;
	struct sock *newsk;
	int err = -1;

	if (!sk) goto out;

	newsk = sk->ops->accept(sk);
	if (newsk) {
		/* 将对方的地址信息记录下来 */
		if (skaddr) {
			skaddr->sin_addr.s_addr = htonl(newsk->daddr);
			skaddr->sin_port = htons(newsk->dport);
		}
		sock_init_data(newsock, newsk);	/* 对struct sock部分做初始化工作 */
		err = 0;
	}
out:
	return err;
}
