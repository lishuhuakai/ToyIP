#include "syshead.h"
#include "liblevelip.h"
#include "ipc.h"
#include "list.h"
#include <assert.h>
#include <pthread.h>
#define RCBUF_LEN 512

static LIST_HEAD(lvlip_socks);
static int socks_count = 0;
//static pthread_rwlock_t lvlip_lock = PTHREAD_RWLOCK_INITIALIZER;

static inline void
lvlip_socks_enqueue(struct lvlip_sock *sk)
{
	//pthread_rwlock_wrlock(&lvlip_lock);
	list_add_tail(&sk->list, &lvlip_socks);
	//pthread_rwlock_unlock(&lvlip_lock);
}

static inline void
lvlip_socks_remove(struct lvlip_sock *sk)
{
	//pthread_rwlock_wrlock(&lvlip_lock);
	list_del_init(&sk->list);
	//pthread_rwlock_unlock(&lvlip_lock);
}

static inline struct lvlip_sock *
lvlip_get_sock(int fd)
{
    struct list_head *item;
    struct lvlip_sock *sock;
	//pthread_rwlock_rdlock(&lvlip_lock);
    list_for_each(item, &lvlip_socks) {
        sock = list_entry(item, struct lvlip_sock, list);
		if (sock->fd == fd) {
			//pthread_rwlock_unlock(&lvlip_lock);
			return sock;
		}
    };
	//pthread_rwlock_unlock(&lvlip_lock);
    return NULL;
};

static int 
is_socket_supported(int domain, int type, int protocol)
{
    if (domain != AF_INET) return 0;
    if ((type != SOCK_STREAM) && (type != SOCK_DGRAM)) return 0;
    if (protocol != 0 && protocol != IPPROTO_TCP) return 0;

    return 1;
}

static int 
init_socket(char *sockname)
{
    struct sockaddr_un addr;
    int i;
    int ret;
    int data_socket;

    /* Create local socket. */
    data_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (data_socket == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));

    /* Connect socket to socket address */

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, sockname);

    ret = connect(data_socket, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
    if (ret == -1) {
        fprintf(stderr, "Error connecting to level-ip. Is it up?\n");
        exit(EXIT_FAILURE);
    }

    return data_socket;
}

static int 
free_socket(int lvlfd)
{
    return close(lvlfd);
}

static int 
transmit_lvlip(int lvlfd, struct ipc_msg *msg, int msglen)
{
    char *buf[RCBUF_LEN];

    // Send mocked syscall to lvl-ip
    if (write(lvlfd, (char *)msg, msglen) == -1) {
        perror("Error on writing IPC");
    }

    // Read return value from lvl-ip
    if (read(lvlfd, buf, RCBUF_LEN) == -1) {
        perror("Could not read IPC response");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) buf;

    if (response->type != msg->type || response->pid != msg->pid) {
        printf("ERR: IPC msg response expected type %d, pid %d\n"
               "                      actual type %d, pid %d\n",
               msg->type, msg->pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *err = (struct ipc_err *) response->data;

    if (err->rc == -1) errno = err->err;

    return err->rc;
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
int 
lvl_socket(int domain, int type, int protocol)
{
    if (!is_socket_supported(domain, type, protocol)) {
		assert(0);
		return -1;
    }
    struct lvlip_sock *sock;
	struct ipc_socket* actual;
    int lvlfd = init_socket("/tmp/lvlip.socket"); /* 返回的是一个文件描述符 */
    sock = lvlip_alloc();	
    sock->lvlfd = lvlfd;
	
	lvlip_socks_enqueue(sock);
    
    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_socket);

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_SOCKET;
    msg->pid = pid;

	actual = (struct ipc_socket *)msg->data;
	actual->domain = domain;
	actual->type = type;
	actual->protocol = protocol;

    int sockfd = transmit_lvlip(sock->lvlfd, msg, msglen);

    if (sockfd == -1) {
        /* Socket alloc failed */
        lvlip_free(sock);
        return -1;
    }

    sock->fd = sockfd;

    return sockfd;
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
int 
lvl_close(int fd)
{
    struct lvlip_sock *sock = lvlip_get_sock(fd);

    if (sock == NULL) {
        /* No lvl-ip IPC socket associated */
		assert(0);
        return -1;
    }

    lvlip_dbg("Close called", sock);
    
    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_close);
    int rc = 0;

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_CLOSE;
    msg->pid = pid;

    struct ipc_close *payload = (struct ipc_close *)msg->data;
    payload->sockfd = fd;

    rc = transmit_lvlip(sock->lvlfd, msg, msglen);
    
	if (rc == 0) {
		lvlip_socks_remove(sock);
		lvlip_free(sock);
	}

	// tofix: sock->lvlfd指向的连接想一种办法关闭,可以借鉴引用计数的思想.
    return rc;
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
int 
lvl_connect(int sockfd, const struct sockaddr_in *addr)
{
    struct lvlip_sock *sock = lvlip_get_sock(sockfd);
	int msglen;
	int pid;
    if (sock == NULL) {
        /* No lvl-ip IPC socket associated */
		assert(0);
        return -1;
    }

    lvlip_dbg("Connect called", sock);
    
    msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_connect);
    pid = getpid();
    
    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_CONNECT;
    msg->pid = pid;

    struct ipc_connect payload = {
        .sockfd = sockfd,
        .addr = *addr,
    };

    memcpy(msg->data, &payload, sizeof(struct ipc_connect));

    return transmit_lvlip(sock->lvlfd, msg, msglen);
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
int 
lvl_bind(int sockfd, const struct sockaddr_in *addr)
{
	struct lvlip_sock *sock = lvlip_get_sock(sockfd);

	if (sock == NULL) {
		return -1;
	}

	lvlip_dbg("Bind called", sock);

	int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_bind);
	int pid = getpid();
	struct ipc_msg *msg = alloca(msglen);
	msg->type = IPC_BIND;
	msg->pid = pid;

	struct ipc_bind payload = {
	.sockfd = sockfd,
	.addr = *addr,
	};

	memcpy(msg->data, &payload, sizeof(struct ipc_bind));
	return transmit_lvlip(sock->lvlfd, msg, msglen);
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
ssize_t 
lvl_write(int sockfd, const void *buf, size_t len)
{
    struct lvlip_sock *sock = lvlip_get_sock(sockfd);

    if (sock == NULL) {
        /* No lvl-ip IPC socket associated */
		assert(0);
        return -1;
    }

    lvlip_dbg("Write called", sock);
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_write) + len;
    int pid = getpid();

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_WRITE;
    msg->pid = pid;

    struct ipc_write payload = {
        .sockfd = sockfd,
        .len = len
    };

    memcpy(msg->data, &payload, sizeof(struct ipc_write));
	struct ipc_write *data = (struct ipc_write *)msg->data;
    memcpy(data->buf, buf, len); /* 实际的数据记录在buf中 */

    return transmit_lvlip(sock->lvlfd, msg, msglen);
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
ssize_t 
lvl_read(int sockfd, void *buf, size_t len)
{
    struct lvlip_sock *sock = lvlip_get_sock(sockfd);
	int pid, msglen, rlen;
	struct ipc_msg *msg;
    if (sock == NULL) {
        /* No lvl-ip IPC socket associated */
		assert(0);
        return -1;
    }

    lvlip_dbg("Read called", sock);

    pid = getpid();
    msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_read);

    msg = alloca(msglen);
    msg->type = IPC_READ;
    msg->pid = pid;

    struct ipc_read payload = {
        .sockfd = sockfd,
        .len = len
    };

    memcpy(msg->data, &payload, sizeof(struct ipc_read));

    /* 向协议栈发送模拟的系统调用 */
    if (write(sock->lvlfd, (char *)msg, msglen) == -1) {
        perror("Error on writing IPC read");
    }

    rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_read) + len;
    char rbuf[rlen];
    memset(rbuf, 0, rlen);

    // Read return value from lvl-ip
    if (read(sock->lvlfd, rbuf, rlen) == -1) {
        perror("Could not read IPC read response");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) rbuf;

    if (response->type != IPC_READ || response->pid != pid) {
        printf("ERR: IPC read response expected: type %d, pid %d\n"
               "                       actual: type %d, pid %d\n",
               IPC_READ, pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *error = (struct ipc_err *) response->data;
    if (error->rc < 0) {
        errno = error->err;
        return error->rc;
    }

    struct ipc_read *data = (struct ipc_read *) error->data;
    if (len < data->len) {
        printf("IPC read received len error: %lu\n", data->len);
        return -1;
    }

    memset(buf, 0, len);
    memcpy(buf, data->buf, data->len);
        
    return data->len;
}


/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
ssize_t 
lvl_sendto(int fd, const void *buf, size_t len,  const struct sockaddr_in *saddr)
{
	struct lvlip_sock *sock = lvlip_get_sock(fd);
	if (sock == NULL) return -1;
	
	lvlip_dbg("Sendto called", sock);
	int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_sendto) + len;
	int pid = getpid();

	struct ipc_msg *msg = alloca(msglen);
	msg->type = IPC_SENDTO;
	msg->pid = pid;

	struct ipc_sendto payload = {
		.sockfd = fd,
		.len = len,
		.addr = *saddr
	};

	memcpy(msg->data, &payload, sizeof(struct ipc_sendto));
	struct ipc_sendto *data = (struct ipc_sendto *)msg->data;
	memcpy(data->buf, buf, len);

    return transmit_lvlip(sock->lvlfd, msg, msglen);
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
ssize_t
lvl_recvfrom(int sockfd, void * buf, size_t len, struct sockaddr_in * address)
{
	struct lvlip_sock *sock = lvlip_get_sock(sockfd);
	int pid, msglen, rlen;
	struct ipc_msg *msg;
	struct ipc_recvfrom *rf;
	if (!sock) return -1;
	
	lvlip_dbg("Recvfrom called", sock);
	pid = getpid();
	
	msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_recvfrom);
	msg = alloca(msglen);
	msg->type = IPC_RECVFROM;
	msg->pid = pid;

	rf = (struct ipc_recvfrom *)msg->data;
	rf->sockfd = sockfd;
	rf->len = len;
	rf->contain_addr = address ? 1 : 0;
	

	if (write(sock->lvlfd, (char *)msg, msglen) == -1) {
		perror("Error on writing IPC recvfrom");
		return -1;
	}

	/* 需要读取的数据的长度 */
	rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_recvfrom) +
		sizeof(struct ipc_err) + len;
	char rbuf[rlen];
	memset(rbuf, 0, rlen);

	if (read(sock->lvlfd, rbuf, rlen) == -1) {
		perror("Could not read IPC recvform response");
		return -1;
	}

	struct ipc_msg *response = (struct ipc_msg *)rbuf;

	if (response->type != IPC_RECVFROM || response->pid != pid) {
        printf("ERR: IPC recvfrom response expected: type %d, pid %d\n"
               "                       actual: type %d, pid %d\n",
               IPC_RECVFROM, pid, response->type, response->pid);
		return -1;
	}

	struct ipc_err *error = (struct ipc_err *)response->data;
	if (error->rc < 0) {
		errno = error->err;
		return error->rc;
	}

	struct ipc_recvfrom *data = (struct ipc_recvfrom*)error->data;
	if (len < data->len) {
		printf("IPC recvfrom received len error: %lu\n", data->len);
	}
	memset(buf, 0, len);
	memcpy(buf, data->buf, data->len);
	if (address)
		*address = data->addr;	/* 对端的地址信息 */
	return data->len;
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
void 
lvl_init() 
{

}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
int
lvl_accept(int sockfd, struct sockaddr_in *addr)
{
	struct lvlip_sock *sock = lvlip_get_sock(sockfd);
	struct ipc_msg *msg;
	int msglen, rlen, pid;
	struct lvlip_sock *new_sock;
	if (sock == NULL) {
		assert(0);
		return -1;
	}

	lvlip_dbg("Accept called", sock);
	msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_accept);
	pid = getpid();
	msg = alloca(msglen);
	msg->type = IPC_ACCEPT;
	msg->pid = pid;

	struct ipc_accept payload = {
	.sockfd = sockfd,
	.contain_addr = addr ? 1 : 0,
	};

	memcpy(msg->data, &payload, sizeof(struct ipc_accept));

	if (write(sock->lvlfd, (char *)msg, msglen) == -1) {
		perror("Error on writing IPC accept");
	}
#define R_LEN (sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_accept))
	rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_accept);
	char rbuf[R_LEN];
	memset(rbuf, 0, rlen);

	/* 读取返回值 */
	if (read(sock->lvlfd, rbuf, rlen) == -1) {
		perror("Could not read IPC accept response");
	}

	struct ipc_msg *response = (struct ipc_msg *)rbuf;
	if (response->type != IPC_ACCEPT || response->pid != pid) {
		printf("ERR: IPC read response expected: type %d, pid %d\n"
			"                       actual: type %d, pid %d\n",
			IPC_ACCEPT, pid, response->type, response->pid);
		return -1;
	}

	struct ipc_err *error = (struct ipc_err *)response->data;
	if (error->rc < 0) {	/* rc < 0 表示出错 */
		errno = error->err;
		return error->rc;
	}

	new_sock = lvlip_alloc();
	new_sock->lvlfd = sock->lvlfd;
	new_sock->fd = error->rc;
	list_add_tail(&new_sock->list, &lvlip_socks);

	struct ipc_accept *data = (struct ipc_accept *)error->data;
	if (addr) {
		memcpy(addr, &data->addr, sizeof(struct sockaddr_in));
	}
	return error->rc;	/* rc记录了函数运行的结果 */
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
int
lvl_listen(int sockfd, int backoff)
{
	struct lvlip_sock *sock = lvlip_get_sock(sockfd);

	if (sock == NULL) {
		return -1;
	}

	lvlip_dbg("Listen called", sock);

	int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_listen);
	int pid = getpid();
	struct ipc_msg *msg = alloca(msglen);
	msg->type = IPC_LISTEN;
	msg->pid = pid;

	struct ipc_listen payload = {
		.sockfd = sockfd,
		.backoff = backoff,
	};

	memcpy(msg->data, &payload, sizeof(struct ipc_listen));
	return transmit_lvlip(sock->lvlfd, msg, msglen);
}