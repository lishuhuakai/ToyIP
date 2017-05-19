#ifndef LIBLEVELIP_H_
#define LIBLEVELIP_H_

#include <poll.h>
#include "list.h"

#define DEBUG_API
#ifdef DEBUG_API
#define lvlip_dbg(msg, sock)                                   \
    do {                                                       \
        printf("lvlip-sock lvlfd %d fd %d: %s\n", sock->lvlfd, \
				sock->fd, msg);								   \
    } while (0)
#else
#define lvlip_dbg(msg, sock)
#endif

struct lvlip_sock {
	struct list_head list;
	int lvlfd;		/* lvlfd用于连接协议栈 */
	int fd;			/* fd才是真正用于连接网络 */
};

static inline struct lvlip_sock *
lvlip_alloc() {
	struct lvlip_sock *sock = (struct lvlip_sock *)malloc(sizeof(struct lvlip_sock));
	memset(sock, 0, sizeof(struct lvlip_sock));
	return sock;
};

static inline void 
lvlip_free(struct lvlip_sock *sock) {
	free(sock);
}

void lvl_init();
int lvl_socket(int domain, int type, int protocol);
int lvl_close(int fd);
int lvl_connect(int sockfd, const struct sockaddr_in *addr);
int lvl_bind(int sockfd, const struct sockaddr_in *addr);
int lvl_listen(int sockfd, int backlog);
int lvl_accept(int sockfd, struct sockaddr_in *);
ssize_t lvl_write(int sockfd, const void *buf, size_t len);
ssize_t lvl_read(int sockfd, void *buf, size_t len);
ssize_t lvl_send(int fd, const void *buf, size_t len, int flags);
ssize_t lvl_sendto(int fd, const void *buf, size_t len, int flags,
			const struct sockaddr *dest_addr, socklen_t dest_len);
ssize_t lvl_recv(int fd, void *buf, size_t len, int flags);
ssize_t lvl_recvfrom(int fd, void * buf, size_t len, int flags, struct sockaddr * address, socklen_t * addrlen);

#endif
