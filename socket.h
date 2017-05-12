#ifndef SOCKET_H
#define SOCKET_H
#include "sock.h"
#include "socket.h"
#include "list.h"
#include "wait.h"
#include <inttypes.h>
#include <bits/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>


#ifdef DEBUG_SOCKET
#define socket_dbg(sock)																			\
    do {																							\
        print_debug("Socket fd %d pid %d state %d sk_state %d flags %d poll %d sport %d dport %d "  \
                    "sock-sleep %d sk-sleep %d recv-q %d send-q %d",								\
                    sock->fd, sock->pid, sock->state, sock->sk->state, sock->flags,					\
                    sock->sk->poll_events,															\
                    sock->sk->sport, sock->sk->dport, sock->sleep.sleeping,							\
                    sock->sk->recv_wait.sleeping, sock->sk->receive_queue.qlen,						\
                    sock->sk->write_queue.qlen);													\
    } while (0)
#else
#define socket_dbg(sock)
#endif


struct socket;

enum socket_state {
	SS_FREE = 0,		// not allocated
	SS_UNCONNECTED,		// 未连接
	SS_CONNECTING,		// 正在连接
	SS_CONNECTED,		// 连接成功
	SS_DISCONNECTING	// 正在断开连接
};

struct sock_type {
	struct sock_ops *sock_ops;	/* sock_ops记录一套对socket的操纵方法 */
	struct net_ops *net_ops;
	int type;
	int protocol;
};

struct sock_ops {
	int (*connect)(struct socket *sock, const struct sockaddr *addr,
		int addr_len, int flags);
	int(*write) (struct socket *sock, const void *buf, int len);
	int(*read)(struct socket *sock, void *buf, int len);
	int(*bind)(struct socket *sock, struct sockaddr *, int addrlen);	/* 绑定到某个地址 */
	int(*close)(struct socket *sock);
	int(*free)(struct socket *sock);
	int(*poll)(struct socket *sock);
	int(*sendto)(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen);
	int(*recvfrom)(int sockfd, void *buf, size_t len, int flags,
		struct sockaddr *src_addr, socklen_t *addrlen);
};

struct net_family {
	int(*create)(struct socket *sock, int protocol);
};

/* socket更加贴近底层,它记录了使用该协议栈的进程id,记录了这个连接的一些属性. 
 * 而sock更多地记录了实际的连接. sock是socket的一部分.
 */
struct socket {
	struct list_head list;
	int fd;
	pid_t pid;
	enum socket_state state;		/* socket正在处于的状态 */
	short type;
	int flags;
	struct sock *sk;
	struct sock_ops *ops;			/* 记录一套对socket操纵的方法 */
	struct wait_lock sleep;
};

struct socket *socket_lookup(int protocol, uint16_t remoteport, uint16_t localport);
void * socket_ipc_open(void *args);
int _socket(pid_t pid, int domain, int type, int protocol);
int _connect(pid_t pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int _write(pid_t pid, int sockfd, const void *buf, const unsigned int count);
int _read(pid_t pid, int sockfd, void* buf, const unsigned int count);
int _bind(pid_t pid, int sockfd, struct sockaddr *skaddr, int addrlen);
int _close(pid_t pid, int sockfd);
int _poll(pid_t pid, int sockfd);
int _fcntl(pid_t pid, int fildes, int cmd, ...);
int socket_free(struct socket *sock);
void socket_debug();

#endif // !SOCKET_H