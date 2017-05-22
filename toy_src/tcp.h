#ifndef TCP_H
#define TCP_H

#include "syshead.h"
#include "ip.h"
#include "timer.h"
#include "utils.h"
#include "sock.h"

#define TCP_HDR_LEN	sizeof(struct tcphdr)
#define TCP_DOFFSET sizeof(struct tcphdr) / 4

#define TCP_FIN	0x01
#define TCP_SYN	0x02
#define TCP_RST	0x04
#define TCP_PSH	0x08
#define TCP_ACK	0x10

#define TCP_URG	0x20
#define TCP_ECN	0x40
#define TCP_WIN 0x80

#define TCP_SYN_BACKOFF 500
#define TCP_CONN_RETRIES 3

#define TCP_OPTLEN_MSS 4
#define TCP_OPT_MSS	  2

#define tcp_sk(sk) ((struct tcp_sock *)sk)

/* tcp首部的大小,tcp头部有4个bit来表示首部长度,首部长度给出了首部中32bit字的数目 */
#define tcp_hlen(tcp) (tcp->hl << 2)

#ifdef DEBUG_TCP
extern const char *tcp_dbg_states[];
#define tcp_in_dbg(hdr, sk, skb)															  \
do {																						  \
		print_debug("TCP %hhu.%hhu.%hhu.%hhu.%u > %hhu.%hhu.%hhu.%hhu.%u: "					  \
			"Flags [S%hhuA%hhuP%hhuF%hhuR%hhu], seq %u:%u, ack %u, win %u",					  \
			sk->daddr >> 24, sk->daddr >> 16, sk->daddr >> 8, sk->daddr >> 0, sk->dport,	  \
			sk->saddr >> 24, sk->saddr >> 16, sk->saddr >> 8, sk->saddr >> 0, sk->sport,	  \
			hdr->syn, hdr->ack, hdr->psh, hdr->fin, hdr->rst, hdr->seq - tcp_sk(sk)->tcb.irs, \
			hdr->seq + skb->dlen - tcp_sk(sk)->tcb.irs,										  \
			hdr->ack_seq - tcp_sk(sk)->tcb.isn, hdr->win);									  \
	} while (0)

#define tcp_out_dbg(hdr, sk, skb)																	  \
    do {																							  \
        print_debug("TCP %hhu.%hhu.%hhu.%hhu.%u > %hhu.%hhu.%hhu.%hhu.%u: "							  \
                    "Flags [S%hhuA%hhuP%hhuF%hhuR%hhu], seq %u:%u, ack %u, win %u",					  \
                    sk->saddr >> 24, sk->saddr >> 16, sk->saddr >> 8, sk->saddr >> 0, sk->sport,	  \
                    sk->daddr >> 24, sk->daddr >> 16, sk->daddr >> 8, sk->daddr >> 0, sk->dport,	  \
                    hdr->syn, hdr->ack, hdr->psh, hdr->fin, hdr->rst, hdr->seq - tcp_sk(sk)->tcb.isn, \
                    hdr->seq + skb->dlen - tcp_sk(sk)->tcb.isn,										  \
                    hdr->ack_seq - tcp_sk(sk)->tcb.irs, hdr->win);									  \
    } while (0)

#define tcp_sock_dbg(msg, sk)																		 \
    do {																						     \
        print_debug("TCP x:%u > %hhu.%hhu.%hhu.%hhu.%u (snd_una %u, snd_nxt %u, snd_wnd %u, "		 \
                    "snd_wl1 %u, snd_wl2 %u, rcv_nxt %u, rcv_wnd %u) state %s: "msg,				 \
                    sk->sport, sk->daddr >> 24, sk->daddr >> 16, sk->daddr >> 8, sk->daddr >> 0,	 \
                    sk->dport, tcp_sk(sk)->tcb.snd_una - tcp_sk(sk)->tcb.isn,						 \
                    tcp_sk(sk)->tcb.snd_nxt - tcp_sk(sk)->tcb.isn, tcp_sk(sk)->tcb.snd_wnd,			 \
                    tcp_sk(sk)->tcb.snd_wl1, tcp_sk(sk)->tcb.snd_wl2,								 \
                    tcp_sk(sk)->tcb.rcv_nxt - tcp_sk(sk)->tcb.irs, tcp_sk(sk)->tcb.rcv_wnd,			 \
                    tcp_dbg_states[sk->state]);														 \
    } while (0)

#define tcp_set_state(sk, state)					\
    do {											\
        tcp_sock_dbg("state is now "#state, sk);	\
        _tcp_set_state(sk, state);					\
    } while (0)

#else
#define tcp_in_dbg(hdr, sk, skb)
#define tcp_out_dbg(hdr, sk, skb)
#define tcp_sock_dbg(msg, sk)
#define tcp_set_state(sk, state)  __tcp_set_state(sk, state)
#endif

struct tcphdr {
	uint16_t sport;		/* 16位源端口号 */
	uint16_t dport;		/* 16位目的端口号 */
	uint32_t seq;		/* 32位序列号 */
	uint32_t ack_seq;	/* 32位确认序列号,一般表示下一个期望收到的数据的序列号 */
	uint8_t rsvd : 4;	
	uint8_t hl : 4;		/* 4位首部长度 */
	uint8_t fin : 1,	/* 发送端完成发送任务 */
		syn : 1,		/* 同步序号用来发起一个连接 */
		rst : 1,		/* 重建连接 */
		psh : 1,		/* 接收方应该尽快将这个报文段交给应用层 */
		ack : 1,		/* 确认序号有效 */
		urg : 1,		/* 紧急指针有效 */
		ece : 1,
		cwr : 1;
	uint16_t win;		/* 16位窗口大小 */
	uint16_t csum;		/* 16位校验和 */
	uint16_t urp;		/* 16位紧急指针 */
	uint8_t data[];
} __attribute__((packed));


struct tcp_options {
	uint16_t options;
	uint16_t mss;
};

struct tcp_opt_mss {
	uint8_t kind;
	uint8_t len;
	uint16_t mss;
} __attribute__((packed));

struct tcpiphdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t proto;
    uint16_t tlen;
} __attribute__((packed));

enum tcp_states {
	TCP_LISTEN,			/* 等待一个连接 */
	TCP_SYN_SENT,		/* 已经发送了一个连接请求,等待对方的回复 */
	TCP_SYN_RECEIVED,   /* 接收到了对方发过来的syn, ack,需要发送确认 */
	TCP_ESTABLISHED,    /* 连接建立成功 */
	TCP_FIN_WAIT_1,
	TCP_FIN_WAIT_2,
	TCP_CLOSE,
	TCP_CLOSE_WAIT,
	TCP_CLOSING,
	TCP_LAST_ACK,
	TCP_TIME_WAIT,
};

/* Transmission Control Block 传输控制块 */
struct tcb {
	/* sending side 发送方,指的是此端 */
	uint32_t snd_una; // send unacknowledge #尚未被确认的数据的起始序列号
	uint32_t snd_nxt; // send next #下一个要发送的数据bit对应的序列号,即seq
	uint32_t snd_wnd; // send window #发送窗口的大小
	uint32_t snd_up;  // send urgent pointer
	uint32_t snd_wl1; // segment sequence number used for last window update
	uint32_t snd_wl2; // segment acknowledgment number used for last window update
	uint32_t isn;	  // initial send sequence number #初始的序列号(自己产生的)
	/* receiving side 接收方,指的是彼端 */
	uint32_t rcv_nxt; // receive next #下一个期望收到的数据的序号,一般用作发给对方的ack序号
	uint32_t rcv_wnd; // receive window #接收窗口的大小
	uint32_t rcv_up;  // receive urgent pointer
	uint32_t irs;	  // initial receive sequence number #接收到的起始序列号(对方的起始序列号)
};

/* tcp_sock在原本sock的基础上增加了很多新的东西. */
struct tcp_sock {
	struct sock sk;
	int fd;
	uint16_t tcp_header_len;	/* tcp头部大小 */
	struct tcb tcb;				/* 传输控制块 */
	uint8_t flags;
	uint8_t backoff;
	struct list_head listen_queue;	/* 等待三次握手中的第二次ack+syn */
	struct list_head accept_queue;	/* 等待三次握手中的最后一次的ack */
	struct list_head list;
	struct wait_lock wait;	/* 等待接收或者连接 */
	//struct wait_lock *wait_connect;	/* 等待被连接 */
	struct tcp_sock *parent;
	struct timer *retransmit;
	struct timer *delack;
	struct timer *keepalive;	/* 保活 */
	struct timer *linger;
	uint8_t delacks;
	uint16_t rmss;				/* remote maximum segment size */ 
	uint16_t smss;				/* 最大报文段长度 */
	struct sk_buff_head ofo_queue; /* ofo_queue用于记录那些
								   没有按照顺序到达的tcp数据报 */
};

static inline struct tcphdr *
tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)(skb->head + ETH_HDR_LEN + IP_HDR_LEN);
}


/* tcp_accept_dequeue 从acccept队列中取出一个sock */
static struct tcp_sock * 
tcp_accept_dequeue(struct tcp_sock *tsk)
{
	struct tcp_sock *newtsk;
	newtsk = list_first_entry(&tsk->accept_queue, struct tcp_sock, list);
	list_del(&newtsk->list);
	list_init(&newtsk->list);
	return newtsk;
}

/* tcp_accept_enqueue 将tsk放入到acccept队列中 */
static inline void
tcp_accept_enqueue(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->list))
		list_del(&tsk->list);
	list_add(&tsk->list, &tsk->parent->accept_queue);
}

/* tcp_sock.c */
int generate_isn();
int tcp_init_sock();
int tcp_init(struct sock *sk);
int tcp_v4_connect(struct sock *sk, const struct sockaddr_in *addr);
int tcp_write(struct sock *sk, const void *buf, int len);
int tcp_read(struct sock *sk, void *buf, int len);
int tcp_recv_notify(struct sock *sk);
int tcp_close(struct sock *sk);
int tcp_free_sock(struct sock *sk);
int tcp_done(struct sock *sk);

void tcp_established_or_syn_recvd_socks_enqueue(struct sock *sk);
void tcp_connecting_or_listening_socks_enqueue(struct sock *sk);
void tcp_established_or_syn_recvd_socks_remove(struct sock *sk);
void tcp_connecting_or_listening_socks_remove(struct sock *sk);

struct sock* tcp_lookup_sock(uint32_t src, uint16_t sport, uint32_t dst, uint16_t dport);

/* tcp.c */
void tcp_clear_timers(struct sock *sk);
void tcp_stop_retransmission_timer(struct tcp_sock *tsk);
void tcp_release_retransmission_timer(struct tcp_sock *tsk);
void tcp_stop_delack_timer(struct tcp_sock *tsk);
void tcp_release_delack_timer(struct tcp_sock *tsk);
void tcp_handle_fin_state(struct sock *sk);
void tcp_enter_time_wait(struct sock *sk);
void _tcp_set_state(struct sock *sk, uint32_t state);
void tcp_in(struct sk_buff *skb);
void tcp_send_delack(uint32_t ts, void *arg);
int tcp_process(struct sock *sk, struct tcphdr *th, struct sk_buff *skb);
void tcp_enter_time_wait(struct sock *sk);
int tcp_udp_checksum(uint32_t saddr, uint32_t daddr, uint8_t proto, uint8_t *data, uint16_t len);
int tcp_v4_checksum(struct sk_buff *skb, uint32_t saddr, uint32_t daddr);
void tcp_select_initial_window(uint32_t *rcv_wnd);

int generate_isn();
uint16_t tcp_generate_port();
struct sock *tcp_alloc_sock();

/*tcp_output.c*/
int tcp_receive(struct tcp_sock *tsk, void *buf, int len);
void tcp_reset_retransmission_timer(struct tcp_sock *tsk);
int tcp_send_challenge_ack(struct sock *sk, struct sk_buff *skb);
int tcp_send_ack(struct sock *sk);
int tcp_send_fin(struct sock *sk);
int tcp_send(struct tcp_sock *tsk, const void *buf, int len);
int tcp_send_synack(struct sock *sk);
int tcp_begin_connect(struct sock *sk);
void tcp_handle_fin_state(struct sock *sk);
int tcp_queue_fin(struct sock *sk);
int tcp_send_reset(struct tcp_sock *tsk);

/*tcp_data.c*/
int tcp_data_queue(struct tcp_sock *tsk, struct tcphdr *th, struct sk_buff *skb);
int tcp_data_dequeue(struct tcp_sock *tsk, void *user_buf, int userlen);

#endif // !TCP_H