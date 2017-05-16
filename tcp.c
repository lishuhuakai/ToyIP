#include "syshead.h"
#include "inet.h"
#include "ip.h"
#include "sock.h"
#include "socket.h"
#include "utils.h"
#include "timer.h"
#include "wait.h"
#include "tcp.h"
#include "checksum.h"

#ifdef DEBUG_TCP
const char *tcp_dbg_states[] = {
	"TCP_LISTEN", "TCP_SYNSENT", "TCP_SYN_RECEIVED", "TCP_ESTABLISHED", "TCP_FIN_WAIT_1",
	"TCP_FIN_WAIT_2", "TCP_CLOSE", "TCP_CLOSE_WAIT", "TCP_CLOSING", "TCP_LAST_ACK", "TCP_TIME_WAIT",
};
#endif


/* tcp_init_segment 将网络字节序的各项全部转化为主机字节序 */
static void
tcp_init_segment(struct tcphdr *th, struct iphdr *ih, struct sk_buff *skb) 
{
	ih->daddr = ntohl(ih->daddr);
	ih->saddr = ntohl(ih->saddr);
	
	th->sport = ntohs(th->sport);		/* 16位源端口号   */
	th->dport = ntohs(th->dport);		/* 16位目的端口号 */
	th->seq = ntohl(th->seq);			/* 32位序列号		*/
	th->ack_seq = ntohl(th->ack_seq);	/* 32位确认序列号 */
	th->win = ntohs(th->win);			/* 16位窗口大小   */
	th->csum = ntohs(th->csum);			/* 校验和		    */
	th->urp = ntohs(th->urp);			/* 16位紧急指针   */

	/* skb中全部都是项全部都是主机字节序 */
	skb->seq = th->seq;					/* 该数据报起始的序列号 */
	skb->dlen = ip_len(ih) - tcp_hlen(th);	/* 实际数据的大小 */
	skb->len = skb->dlen + th->syn + th->fin; 
	skb->end_seq = skb->seq + skb->dlen; /* 该数据报终止的序列号 */
	skb->payload = th->data;
}

static void
tcp_clear_queues(struct tcp_sock *tsk) 
{
	pthread_mutex_lock(&tsk->ofo_queue.lock);
	skb_queue_free(&tsk->ofo_queue);
	pthread_mutex_unlock(&tsk->ofo_queue.lock);
}

void
tcp_in(struct sk_buff *skb)
{
	struct sock *sk;
	struct iphdr *iph;
	struct tcphdr *th;

	iph = ip_hdr(skb);		 
	th = (struct tcphdr *)iph->data; 

	tcp_init_segment(th, iph, skb);

	/* 这里寻找的sk本来就是一个tcp_sock对象 */
	sk = tcp_lookup_sock(iph->saddr, th->sport, iph->daddr, th->dport);

	if (sk == NULL) {
		print_err("No TCP socket for sport %d dport %d\n",
			th->sport, th->dport);
		free_skb(skb);
		return;
	}

	tcp_in_dbg(th, sk, skb);
	tcp_input_state(sk, th, skb);
}


int
tcp_v4_checksum(struct sk_buff *skb, uint32_t saddr, uint32_t daddr)
{
	return tcp_udp_checksum(saddr, daddr, IP_TCP, skb->data, skb->len);
}


void 
_tcp_set_state(struct sock *sk, uint32_t state)
{
	sk->state = state;
}

/* generate_port 随机产生接口 */
uint16_t 
tcp_generate_port()
{
	/* todo: 更好的办法来设置port */
	static int port = 40000;
	return ++port + (timer_get_tick() % 10000);
}

int
generate_isn()
{
	/* todo: 更好的方法来产生isn */
	return (int)time(NULL) *rand();
}




int
tcp_free(struct sock *sk)
{
	struct tcp_sock *tsk = tcp_sk(sk);
	pthread_mutex_lock(&sk->lock);
	tcp_set_state(sk, TCP_CLOSE);
	tcp_clear_timers(sk);
	tcp_clear_queues(tsk);
	pthread_mutex_unlock(&sk->lock);

	wait_wakeup(&sk->sock->sleep);
	return 0;
}

int
tcp_done(struct sock *sk)
{
	tcp_free(sk);
	return socket_free(sk->sock);
}

void
tcp_clear_timers(struct sock *sk)
{
	struct tcp_sock *tsk = tcp_sk(sk);
	pthread_mutex_lock(&sk->write_queue.lock);
	tcp_stop_rto_timer(tsk);
	tcp_stop_delack_timer(tsk);
	pthread_mutex_unlock(&sk->write_queue.lock);
	timer_cancel(tsk->keepalive);
}

void 
tcp_stop_rto_timer(struct tcp_sock *tsk)
{
	if (tsk) {
		timer_cancel(tsk->retransmit);
		tsk->retransmit = NULL;
	}
}

void
tcp_release_rto_timer(struct tcp_sock *tsk)
{
	if (tsk) {
		timer_release(tsk->retransmit);
		tsk->retransmit = NULL;
	}
}

void
tcp_stop_delack_timer(struct tcp_sock *tsk)
{
	timer_cancel(tsk->delack);
	tsk->delack = NULL;
}

void
tcp_release_delack_timer(struct tcp_sock *tsk)
{
	timer_release(tsk->delack);
	tsk->delack = NULL;
}

void
tcp_handle_fin_state(struct sock *sk)
{
	switch (sk->state)
	{
		case TCP_CLOSE_WAIT:
			tcp_set_state(sk, TCP_LAST_ACK);
			break;
		case TCP_ESTABLISHED:
			tcp_set_state(sk, TCP_FIN_WAIT_1);
			break;
	default:
		break;
	}
}

static void
tcp_linger(uint32_t ts, void *arg)
{
	struct sock *sk = (struct sock *)arg;
	struct tcp_sock *tsk = tcp_sk(sk);
	timer_release(tsk->linger);		/* 释放定时器 */
	tsk->linger = NULL;
	tcp_done(sk);		/* 彻底结束这个连接 */
}

void
tcp_enter_time_wait(struct sock *sk)
{
	/* 进入TIME_WAIT状态 */
	struct tcp_sock *tsk = tcp_sk(sk);
	tcp_set_state(sk, TCP_TIME_WAIT);
	tcp_clear_timers(sk);
	timer_cancel(tsk->linger);
	tsk->linger = timer_add(3000, &tcp_linger, sk);
}

