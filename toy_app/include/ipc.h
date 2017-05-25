#ifndef IPC_H_
#define IPC_H_

#include "syshead.h"
#include "list.h"
#include <sys/types.h>

#define DEBUG_IPC
#ifdef DEBUG_IPC
#define ipc_dbg(msg, th)													\
    do {																	\
        print_debug("IPC sockets count %d, current sock %d, tid %lu: %s",	\
                    conn_count, th->sock, th->id, msg);						\
    } while (0)
#else
#define ipc_dbg(msg, th)
#endif


#define IPC_SOCKET	 0x0001
#define IPC_CONNECT  0x0002
#define IPC_WRITE    0x0003
#define IPC_READ     0x0004
#define IPC_CLOSE    0x0005
#define IPC_BIND	 0x0006
#define IPC_ACCEPT   0x0007
#define IPC_LISTEN   0x0008
#define IPC_SENDTO   0x0009
#define IPC_RECVFROM 0x000a

struct ipc_thread {
    struct list_head list;
    int sock;
    pthread_t id;
};

struct ipc_msg {
    uint16_t type;
    pid_t pid;
    uint8_t data[];
} __attribute__((packed));

struct ipc_err {
    int rc;				/* 用于记录函数运行的结果 */
    int err;			/* 用于记录errno */
    uint8_t data[];
} __attribute__((packed));

/* ipc_socket主要用于传递socket函数的参数 */
struct ipc_socket {
    int domain;
    int type;
    int protocol;
} __attribute__((packed));

/* ipc_connect主要用于传递connnect函数的参数 */
struct ipc_connect {
    int sockfd;
    struct sockaddr_in addr;
} __attribute__((packed));

struct ipc_accept {
	int sockfd;
	int contain_addr;	/* 是否需要包含地址信息 */
	struct sockaddr_in addr;
} __attribute__((packed));

struct ipc_recvfrom {
	int sockfd;
	size_t len;
	int contain_addr;	/* 是否包含了地址信息 */
	struct sockaddr_in addr;
	uint8_t buf[];
} __attribute__((packed));

struct ipc_bind {
	int sockfd;
	struct sockaddr_in addr;
} __attribute__((packed));

struct ipc_write {
    int sockfd;
    size_t len;
    uint8_t buf[];
} __attribute__((packed));

struct ipc_sendto {
	int sockfd;
	size_t len;
	struct sockaddr_in addr;
	uint8_t buf[];
} __attribute__((packed));


struct ipc_listen {
	int sockfd;
	int backoff;
} __attribute__((packed));

struct ipc_read {
    int sockfd;
    size_t len;
    uint8_t buf[];
} __attribute__((packed));

struct ipc_close {
    int sockfd;
} __attribute__((packed));

#endif
