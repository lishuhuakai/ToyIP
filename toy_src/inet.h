#ifndef INET_H
#define INET_H

#include "syshead.h"
#include "socket.h"
#include "skbuff.h"

int inet_create(struct socket *sock, int protocol);
int inet_socket(struct socket *sock, int protocol);
int inet_listen(struct socket *sock, int backlog);
int inet_connect(struct socket *sock, const struct sockaddr_in *addr);
int inet_accept(struct socket *sock, struct socket *newsock, struct sockaddr_in* skaddr);
int inet_bind(struct socket *sock, struct sockaddr_in * skaddr);
int inet_write(struct socket *sock, const void *buf, int len);
int inet_read(struct socket *sock, void *buf, int len);
int inet_close(struct socket *sock);
int inet_free(struct socket *sock);
int inet_sendto(struct socket *sock, const void *buf, size_t len,
	const struct sockaddr_in *dest_addr);
int inet_recvfrom(struct socket *sock, void *buf, size_t len,
	struct sockaddr_in *src_addr);

#endif // !INET_H