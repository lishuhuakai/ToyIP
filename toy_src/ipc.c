#include "syshead.h"
#include "utils.h"
#include "ipc.h"
#include "socket.h"
#include "udp.h"

#define IPC_BUFLEN 4096

static LIST_HEAD(connections);	/* connections是由struct ipc_thread构成的链 */
static pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
static int conn_count = 0;

static inline void
ipc_connections_enqueue(struct ipc_thread* th)
{
	pthread_rwlock_wrlock(&lock);
	list_add_tail(&th->list, &connections); /* 将th->list加入到connections的尾部 */
	conn_count++;
	pthread_rwlock_unlock(&lock);
}

static inline void
ipc_connections_remove(struct ipc_thread *th)
{
	pthread_rwlock_wrlock(&lock);
	list_del_init(&th->list);
	conn_count--;
	pthread_rwlock_unlock(&lock);
}

static struct ipc_thread *
ipc_alloc_thread(int sock)
{
	struct ipc_thread *th = calloc(sizeof(struct ipc_thread), 1);
	list_init(&th->list);
	th->sock = sock;		/* sock仅仅只是一个标记 */
	
	ipc_connections_enqueue(th);
	
	ipc_dbg("New IPC socket allocated", th);
	return th;
}

static void
ipc_free_thread(int sock)
{
	struct list_head *item, *tmp = NULL;
	struct ipc_thread *th = NULL;

	pthread_rwlock_rdlock(&lock);
	list_for_each_safe(item, tmp, &connections) {
		th = list_entry(item, struct ipc_thread, list);

		if (th->sock == sock) {		/* sock类似于文件描述符 */
			ipc_connections_remove(th);
			ipc_dbg("IPC socket deleted", th);
			close(th->sock);
			free(th);
			break;
		}
	}
	pthread_rwlock_unlock(&lock);
}

/**\
 * ipc_write_rc 用于对付那些没有数据要返回的函数.
\**/
static int 
ipc_write_rc(int sockfd, pid_t pid, uint16_t type, int rc)
{
	/*
	 返回的数据示意图如下:
	 +----------+----------+
	 | ipc_msg  | ipc_err  |        
	 +----------+----------+
	 
	 */
	int resplen = sizeof(struct ipc_msg) + sizeof(struct ipc_err);
	struct ipc_msg *response = alloca(resplen);	 /* 在栈上动态分配内存 */

	if (response == NULL) {
		print_err("Could not allocate memory for IPC write response\n");
		return -1;
	}

	response->type = type;
	response->pid = pid;

	struct ipc_err err;

	if (rc < 0) {
		err.err = -rc;
		err.rc = -1;
	}
	else {
		err.err = 0;
		err.rc = rc;
	}

	memcpy(response->data, &err, sizeof(struct ipc_err));	/* 直接拷贝err */

	if (write(sockfd, (char *)response, resplen) == -1) {	/* 往sock中写入数据 */
		perror("Error on writing IPC write response");
	}
	return 0;
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

/**\
 * ipc_read函数用于读取数据.
\**/
static int
ipc_read(int sockfd, struct ipc_msg *msg)
{
	struct ipc_read *requested = (struct ipc_read *)msg->data;
	pid_t pid = msg->pid;
	int rlen = -1;
	char rbuf[requested->len];
	memset(rbuf, 0, requested->len);
	/* pid和sockfd可以唯一确定一个socket */
	rlen = _read(pid, requested->sockfd, rbuf, requested->len);
	int resplen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_read) + rlen;
	struct ipc_msg *response = alloca(resplen);
	struct ipc_err *error = (struct ipc_err *)response->data;
	struct ipc_read *actual = (struct ipc_read *)error->data;

	if (response == NULL) {
		print_err("Could not allocate memory for IPC read response\n");
		return -1;
	}

	response->type = IPC_READ;
	response->pid = pid;

	error->rc = rlen < 0 ? -1 : rlen;
	error->err = rlen < 0 ? -rlen : 0;

	actual->sockfd = requested->sockfd;
	actual->len = rlen;
	memcpy(actual->buf, rbuf, rlen > 0 ? rlen : 0);
	
	if (write(sockfd, (char *)response, resplen) == -1) {
		perror("Error on writing IPC write response");
	}

	return 0;
}

static int
ipc_sendto(int sockfd, struct ipc_msg *msg)
{
	struct ipc_sendto *payload = (struct ipc_sendto *)msg->data;
	pid_t pid = msg->pid;
	int rc = -1;
	int dlen = payload->len - IPC_BUFLEN;
	char buf[payload->len];
	
	memset(buf, 0, payload->len);
	memcpy(buf, payload->buf, payload->len > IPC_BUFLEN ? IPC_BUFLEN : payload->len);

	if (payload->len > IPC_BUFLEN) {
		int res = read(sockfd, buf + IPC_BUFLEN, payload->len - IPC_BUFLEN);
		if (res == -1) {
			perror("Read on IPC payload guard");
			return -1;
		}
		else if (res != dlen) {
			print_err("Hmm, we did not read exact payload amount in IPC write\n");
		}
	}
	rc = _sendto(pid, payload->sockfd, buf, payload->len, &payload->addr);
	return ipc_write_rc(sockfd, pid, IPC_SENDTO, rc);
}

static int
ipc_recvfrom(int sockfd, struct ipc_msg *msg)
{
	struct ipc_recvfrom *requested = (struct ipc_recvfrom *)msg->data;
	pid_t pid = msg->pid;
	int rlen = -1;
	char rbuf[requested->len];
	struct sockaddr_in *saddr;
	memset(rbuf, 0, requested->len);

	saddr = requested->contain_addr ? &requested->addr: NULL;

	/* pid和sockfd可以唯一确定一个socket */
	rlen = _recvfrom(pid, requested->sockfd, rbuf, requested->len, saddr);
	int resplen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_recvfrom) + rlen;
	struct ipc_msg *response = alloca(resplen);
	struct ipc_err *error = (struct ipc_err *)response->data;
	struct ipc_recvfrom *actual = (struct ipc_recvfrom *)error->data;

	if (response == NULL) {
		print_err("Could not allocate memory for IPC read response\n");
		return -1;
	}

	response->type = IPC_RECVFROM;
	response->pid = pid;

	error->rc = rlen < 0 ? -1 : rlen;
	error->err = rlen < 0 ? -rlen : 0;

	actual->sockfd = requested->sockfd;
	actual->len = rlen;
	if (saddr) {	/* 拷贝对方的地址信息 */
		actual->addr = *saddr;
	}
	memcpy(actual->buf, rbuf, rlen > 0 ? rlen : 0);

	if (write(sockfd, (char *)response, resplen) == -1) {
		perror("Error on writing IPC recvfrom response");
	}

	return 0;
}


static int
ipc_write(int sockfd, struct ipc_msg *msg)
{
	struct ipc_write *payload = (struct ipc_write *)msg->data;
	pid_t pid = msg->pid;
	int rc = -1;
	int dlen = payload->len - IPC_BUFLEN;
	char buf[payload->len];
	memset(buf, 0, payload->len);
	memcpy(buf, payload->buf, payload->len > IPC_BUFLEN ? IPC_BUFLEN : payload->len);

	if (payload->len > IPC_BUFLEN) {
		int res = read(sockfd, buf + IPC_BUFLEN, payload->len - IPC_BUFLEN);
		if (res == -1) {
			perror("Read on IPC payload guard");
			return -1;
		}
		else if (res != dlen) {
			print_err("Hmm, we did not read exact payload amount in IPC write\n");
		}
	}
	rc = _write(pid, payload->sockfd, buf, payload->len);
	return ipc_write_rc(sockfd, pid, IPC_WRITE, rc);
}

static int
ipc_connect(int sockfd, struct ipc_msg *msg)
{
	struct ipc_connect *payload = (struct ipc_connect *)msg->data;
	pid_t pid = msg->pid;
	int rc = -1;
	rc = _connect(pid, payload->sockfd, &payload->addr);
	return ipc_write_rc(sockfd, pid, IPC_CONNECT, rc); /* 所谓的IPC,只是自己定义的一套规则吗? */
}

static int
ipc_listen(int sockfd, struct ipc_msg *msg)
{
	struct ipc_listen *payload = (struct ipc_listen *)msg->data;
	pid_t pid = msg->pid;
	int rc = -1;
	rc = _listen(pid, payload->sockfd, payload->backoff);
	return ipc_write_rc(sockfd, pid, IPC_LISTEN, rc); /* 所谓的IPC,只是自己定义的一套规则吗? */
}

/**\
 * ipc_bind调用下层的bind函数,模拟bind函数的功能. 
\**/
static int
ipc_bind(int sockfd, struct ipc_msg *msg)
{
	struct ipc_bind *payload = (struct ipc_bind *)msg->data;
	pid_t pid = msg->pid;
	int rc = -1;
	rc = _bind(pid, payload->sockfd, &payload->addr);
	return ipc_write_rc(sockfd, pid, IPC_BIND, rc);
}


static int
ipc_accept(int sockfd, struct ipc_msg *msg)
{
	struct ipc_accept *payload = (struct ipc_accept *)msg->data;
	pid_t pid = msg->pid;
	int rc = -1;
	struct socket *sock;
	struct sockaddr_in *addr = payload->contain_addr ? alloca(sizeof(struct sockaddr)) : NULL;
	rc = _accept(pid, payload->sockfd, addr);	/* 如果rc > 0,那么rc是对应连接的文件描述符 */

	/* acccept的函数,我们必须要自己回复. */
	int resplen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_accept);
	struct ipc_msg *response = alloca(resplen);
	struct ipc_err *error = (struct ipc_err *)response->data;
	struct ipc_accept *acc = (struct ipc_accept *)error->data;

	if (response == NULL) {
		print_err("Could not allocate memorty for IPC accept response\n");
		return -1;
	}

	response->type = IPC_ACCEPT;
	response->pid = pid;

	error->rc = rc;
	error->err = 0; // tofix:

	acc->sockfd = sockfd;
	if (payload->contain_addr)
		memcpy(&acc->addr, addr, sizeof(struct sockaddr_in));
	if (write(sockfd, (char *)response, resplen) == -1) {
		perror("Error on writing IPC accept response");
	}
	return 0;
}

static int
ipc_socket(int sockfd, struct ipc_msg *msg)
{
	struct ipc_socket *sock = (struct ipc_socket *)msg->data;
	pid_t pid = msg->pid;
	int rc = -1;

	rc = _socket(pid, sock->domain, sock->type, sock->protocol);
	return ipc_write_rc(sockfd, pid, IPC_SOCKET, rc);
}

int 
ipc_close(int sockfd, struct ipc_msg *msg)
{
	struct ipc_close *payload = (struct ipc_close *)msg->data;
	pid_t pid = msg->pid;
	int rc = -1;

	rc = _close(pid, payload->sockfd);
	rc = ipc_write_rc(sockfd, pid, IPC_CLOSE, rc);
	return rc;
}


/**\
 * demux_ipc_socket_call 更多的是实现消息的分发.
\**/
static int
demux_ipc_socket_call(int sockfd, char *cmdbuf, int blen)
{
	struct ipc_msg *msg = (struct ipc_msg *)cmdbuf;

	switch (msg->type) {
	case IPC_SOCKET:
		return ipc_socket(sockfd, msg);
	case IPC_CONNECT:
		return ipc_connect(sockfd, msg);
	case IPC_WRITE:
		return ipc_write(sockfd, msg);
	case IPC_READ:
		return ipc_read(sockfd, msg);
	case IPC_BIND:
		return ipc_bind(sockfd, msg);
	case IPC_ACCEPT:
		return ipc_accept(sockfd, msg);
	case IPC_CLOSE:
		return ipc_close(sockfd, msg);
	case IPC_LISTEN:
		return ipc_listen(sockfd, msg);
	case IPC_SENDTO:
		return ipc_sendto(sockfd, msg);
	case IPC_RECVFROM:
		return ipc_recvfrom(sockfd, msg);
	default:
		print_err("No such IPC type %d\n", msg->type);
		break;
	}
	return 0;
}

void *
socket_ipc_open(void *args) {
	int blen = IPC_BUFLEN;
	char buf[IPC_BUFLEN];
	int sockfd = *(int *)args;
	int rc = -1;

	while ((rc = read(sockfd, buf, blen)) > 0) {
		rc = demux_ipc_socket_call(sockfd, buf, blen);	/* 分发 */

		if (rc == -1) {
			printf("Error on demuxing IPC socket call\n");
			close(sockfd);
			return NULL;
		}
	}
	ipc_free_thread(sockfd);

	if (rc == -1)
		perror("socket ipc read");

	return NULL;
}

/**\
 * start_ipc_listener用于监听来自别的应用发送来的函数调用.
\**/
void *
start_ipc_listener()
{
	int fd, rc, datasock;
	struct sockaddr_un un;
	char *sockname = "/tmp/lvlip.socket";

	unlink(sockname);

	if (strnlen(sockname, sizeof(un.sun_path)) == sizeof(un.sun_path)) {
		/* 路径过长 */
		print_err("Path for UNIX socket is too long\n");
		exit(-1);
	}

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("IPC listener UNIX socket");
		exit(EXIT_FAILURE);
	}

	memset(&un, 0, sizeof(struct sockaddr_un));
	un.sun_family = AF_UNIX;

	strncpy(un.sun_path, sockname, sizeof(un.sun_path) - 1);

	rc = bind(fd, (const struct sockaddr *)&un, sizeof(struct sockaddr_un));

	if (rc == -1) {
		perror("IPC bind");
		exit(EXIT_FAILURE);
	}

	rc = listen(fd, 20);
	
	if (rc == -1) {
		perror("IPC listen");
		exit(EXIT_FAILURE);
	}

	for (;;) {
		datasock = accept(fd, NULL, NULL);
		if (datasock == -1) {
			perror("IPC accept");
			exit(EXIT_FAILURE);
		}

		struct ipc_thread *th = ipc_alloc_thread(datasock);

		if (pthread_create(&th->id, NULL, &socket_ipc_open, &datasock) != 0) {
			printf("Error on socket thread creation\n");
			exit(1);
		}
	}
	close(fd);
	unlink(sockname);
	return NULL;
}