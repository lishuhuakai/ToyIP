#include "syshead.h"
#include "utils.h"
#include "tcp.h"
#include "ip.h"
#include "skbuff.h"
#include "timer.h"

static void tcp_retransmission_timeout(uint32_t ts, void *arg);


static struct sk_buff *
tcp_alloc_skb(int optlen, int size)
{
	// optlen表示tcp首部选项的大小
	// 这里要特别注意一下,因为忘记了TCP_HDR_LEN导致出错
	// ===============================================
	int reserved = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + optlen + size; // 这里的一个错误弄得我好苦!
	struct sk_buff *skb = alloc_skb(reserved);

	skb_reserve(skb, reserved); // skb->data部分留出reserved个字节
	skb->protocol = IP_TCP;
	skb->dlen = size;	// dlen表示数据的大小

	return skb;
}

static int
tcp_write_options(struct tcphdr *th, struct tcp_options *opts, int optlen)
{
	struct tcp_opt_mss *opt_mss = (struct tcp_opt_mss *)th->data;

	opt_mss->kind = TCP_OPT_MSS;
	opt_mss->len = TCP_OPTLEN_MSS;
	opt_mss->mss = htons(opts->mss);

	th->hl = TCP_DOFFSET + (optlen / 4);
	return 0;
}

static int 
tcp_syn_options(struct sock *sk, struct tcp_options *opts)
{
	struct tcp_sock *tsk = tcp_sk(sk);
	int optlen = 0;

	opts->mss = tsk->rmss;
	optlen += TCP_OPTLEN_MSS;
	return optlen;
}

static int 
tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, uint32_t seq)
{
	struct tcp_sock *tsk = tcp_sk(sk);
	struct tcb *tcb = &tsk->tcb;
	struct tcphdr *thdr = tcp_hdr(skb);  // tcp头部信息

	if (thdr->hl == 0) thdr->hl = TCP_DOFFSET;

	skb_push(skb, thdr->hl * 4); // hl表示tcp头部大小

	// 填充头部信息
	thdr->sport = sk->sport;
	thdr->dport = sk->dport;
	thdr->seq = seq;		// 分组的序号
	thdr->ack_seq = tcb->rcv_nxt; // 携带一个确认序号
	thdr->win = tcb->rcv_wnd;		// 接收窗口的大小
	thdr->csum = 0;
	thdr->urp = 0;
	thdr->rsvd = 0;

	tcp_out_dbg(thdr, sk, skb);

	// fix:
	// skb的seq和end_seq好像并没有什么用处
	skb->seq = tcb->snd_una;		// 为什么要记录为确认的序列号
	skb->end_seq = tcb->snd_una + skb->dlen; // 终止序列号

	//thdr->hl = htons(thdr->hl);
	thdr->sport = htons(thdr->sport);
	thdr->dport = htons(thdr->dport);
	thdr->seq = htonl(thdr->seq);
	thdr->ack_seq = htonl(thdr->ack_seq);
	thdr->win = htons(thdr->win);
	thdr->csum = htons(thdr->csum);
	thdr->urp = htons(thdr->urp);
	// tcp首部的检验和,需要检验首部和数据,在计算检验和时,要在TCP报文段的前面加上12字节伪首部
	/*
		TCP伪首部
			4						4			   1     1       2
	   +--------------------+-------------------+-----+-----+----------+
	   | 源ip地址				| 目的ip地址			|0	  |	6	|TCP长度	   |
	   +--------------------+-------------------+-----+-----+----------+
	   
	 */
	thdr->csum = tcp_v4_checksum(skb, htonl(sk->saddr), htonl(sk->daddr));

	return ip_output(sk, skb);
}

static int
tcp_queue_transmit_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tsk = tcp_sk(sk);
	struct tcb *tcb = &tsk->tcb;  // 传输控制块
	int rc = 0;

	pthread_mutex_lock(&sk->write_queue.lock);

	if (skb_queue_empty(&sk->write_queue)) {
		tcp_rearm_rto_timer(tsk);
	}

	skb_queue_tail(&sk->write_queue, skb);	// 将skb加入到发送队列的尾部
	rc = tcp_transmit_skb(sk, skb, tcb->snd_nxt);
	tcb->snd_nxt += skb->dlen;
	pthread_mutex_unlock(&sk->write_queue.lock);
	return rc;
}

int
tcp_send_synack(struct sock *sk)
{
	if (sk->state != TCP_SYN_SENT) {
		print_err("TCP synack: Socket was not in correct state (SYN_SENT)\n");
		return 1;
	}

	struct sk_buff *skb;
	struct tcphdr *th;
	struct tcb *tcb = &tcp_sk(sk)->tcb;
	int rc = 0;

	skb = tcp_alloc_skb(0, 0);
	th = tcp_hdr(skb);

	th->syn = 1;
	th->ack = 1;
	// 不消耗序列号
	rc = tcp_transmit_skb(sk, skb, tcb->snd_nxt);
	free_skb(skb);

	return rc;
}

void
tcp_send_delack(uint32_t ts, void *arg)
{
	struct sock *sk = (struct sock *)arg;
	struct tcp_sock *tsk = tcp_sk(sk);

	tsk->delacks = 0;
	tcp_release_delack_timer(tsk);
	tcp_send_ack(sk);
}

// tcp_send_ack 发送ack
int
tcp_send_ack(struct sock *sk)
{
	if (sk->state == TCP_CLOSE) 
		return 0;

	struct sk_buff *skb;
	struct tcphdr *th;
	struct tcb *tcb = &tcp_sk(sk)->tcb;
	int rc = 0;

	skb = tcp_alloc_skb(0, 0);  // 需要重新分配数据块,不包含tcp选项,不包含数据

	th = tcp_hdr(skb); // th指向要发送数据的tcp头部
	th->ack = 1;

	rc = tcp_transmit_skb(sk, skb, tcb->snd_nxt);
	free_skb(skb);

	return rc;
}

static int
tcp_send_syn(struct sock *sk)
{
	if (sk->state != TCP_SYN_SENT && sk->state != TCP_CLOSE && sk->state != TCP_LISTEN) {
		print_err("Socket was not in correct state (closed or listen)\n");
		return 1;
	}

	struct sk_buff *skb;
	struct tcphdr *th;
	struct tcp_options opts = { 0 };
	int tcp_options_len = 0;

	tcp_options_len = tcp_syn_options(sk, &opts);	// tcp选项的长度
	skb = tcp_alloc_skb(tcp_options_len, 0); // 需要发送tcp选项
	th = tcp_hdr(skb);		// 指向tcp头部

	tcp_write_options(th, &opts, tcp_options_len);
	sk->state = TCP_SYN_SENT;  // 客户端发送了SYN之后,进入SYN_SNET状态
	th->syn = 1;

	return tcp_queue_transmit_skb(sk, skb);
}


int
tcp_send_fin(struct sock *sk)
{
	if (sk->state == TCP_CLOSE) return 0;
	struct tcphdr *th;
	struct sk_buff *skb;
	int rc = 0;

	skb = tcp_alloc_skb(0, 0);

	th = tcp_hdr(skb);
	th->fin = 1;
	th->ack = 1;

	rc = tcp_queue_transmit_skb(sk, skb);

	return rc;
}

void 
tcp_select_initial_window(uint32_t *rcv_wnd)
{
	*rcv_wnd = 44477;
}

static void
tcp_notify_user(struct sock *sk)
{
	switch (sk->state) {
	case TCP_CLOSE_WAIT:
		wait_wakeup(&sk->sock->sleep);
		break;

	}
}

static void
tcp_connect_rto(uint32_t ts, void *arg)
{
	struct tcp_sock *tsk = (struct tcp_sock *)arg;
	struct tcb *tcb = &tsk->tcb;
	struct sock *sk = &tsk->sk;

	tcp_release_rto_timer(tsk);

	if (sk->state != TCP_ESTABLISHED) {
		if (tsk->backoff > TCP_CONN_RETRIES) {
			tsk->sk.err = -ETIMEDOUT;  // 超时
			tcp_free(sk);
		}
		else {
			pthread_mutex_lock(&sk->write_queue.lock);

			struct sk_buff *skb = write_queue_head(sk);

			if (skb) {
				skb_reset_header(skb);
				tcp_transmit_skb(sk, skb, tcb->snd_una);

				tsk->backoff++;
				tcp_rearm_rto_timer(tsk);
			}
			pthread_mutex_unlock(&sk->write_queue.lock);
		}
	}
	else {
		print_err("TCP connect RTO triggered even when Established\n");
	}

}


static void
tcp_retransmission_timeout(uint32_t ts, void *arg)
{
	struct tcp_sock *tsk = (struct tcp_sock *)arg;
	struct tcb *tcb = &tsk->tcb;
	struct sock *sk = &tsk->sk;

	pthread_mutex_lock(&sk->write_queue.lock);
	tcp_release_rto_timer(tsk);

	struct sk_buff *skb = write_queue_head(sk);

	if (!skb) {
		tcp_sock_dbg("TCP RTO queue empty, notifying user", sk);
		tcp_notify_user(sk);
		goto unlock;
	}

	struct tcphdr *th = tcp_hdr(skb);
	skb_reset_header(skb);

	tcp_transmit_skb(sk, skb, tcb->snd_una);
	tsk->retransmit = timer_add(500, &tcp_retransmission_timeout, tsk);

	if (th->fin) {
		tcp_handle_fin_state(sk);
	}

unlock:
	pthread_mutex_unlock(&sk->write_queue.lock);
}

// tcp_rearm_rto_timer 用于重新设置重传定时器
void
tcp_rearm_rto_timer(struct tcp_sock *tsk)
{
	struct sock *sk = &tsk->sk;
	tcp_release_rto_timer(tsk);	// 释放掉之前的重传定时器

	if (sk->state == TCP_SYN_SENT) {	// BACKOFF 貌似是退避时间
		tsk->retransmit = timer_add(TCP_SYN_BACKOFF << tsk->backoff, &tcp_connect_rto, tsk);
	}
	else {
		// 500秒超时重传
		tsk->retransmit = timer_add(500, &tcp_retransmission_timeout, tsk);
	}
}

int 
tcp_connect(struct sock *sk)
{
	struct tcp_sock *tsk = tcp_sk(sk);
	struct tcb *tcb = &tsk->tcb;
	int rc = 0;

	tsk->tcp_header_len = sizeof(struct tcphdr);
	tcb->isn = generate_isn();  // isn是随机产生的一个序列号
	tcb->snd_wnd = 0;
	tcb->snd_wl1 = 0;

	tcb->snd_una = tcb->isn;
	tcb->snd_up = tcb->isn;	
	tcb->snd_nxt = tcb->isn;
	tcb->rcv_nxt = 0;

	tcp_select_initial_window(&tsk->tcb.rcv_wnd); // 接收窗口的大小

	rc = tcp_send_syn(sk);
	tcb->snd_nxt++;  // 消耗一个序列号
	return rc;
}

// tcp_send 发送tcp数据
int 
tcp_send(struct tcp_sock *tsk, const void *buf, int len)
{
	struct sk_buff *skb;
	struct tcphdr *th;
	int slen = len;
	int mss = tsk->smss;
	int dlen = 0;

	while (slen > 0) {
		dlen = slen > mss ? mss : slen; // 一个tcp报文最多只能发送mss个字节tcp数据
		slen -= dlen;

		skb = tcp_alloc_skb(0, dlen); // tcp头部选项0字节,数据大小dlen字节
		skb_push(skb, dlen);
		memcpy(skb->data, buf, dlen);

		buf += dlen;
		th = tcp_hdr(skb);
		th->ack = 1;

		if (slen == 0) {
			th->psh = 1;	// 紧急数据
		}

		if (tcp_queue_transmit_skb(&tsk->sk, skb) == -1) {
			perror("Error on TCP skb queueing");
		}
	}
	return len;
}

// tcp_send_reset 向对端发送RST
int
tcp_send_reset(struct tcp_sock *tsk)
{
	struct sk_buff *skb;
	struct tcphdr *th;
	struct tcb *tcb;
	int rc = 0;

	skb = tcp_alloc_skb(0, 0);
	th = tcp_hdr(skb);
	tcb = &tsk->tcb;

	th->rst = 1;
	tcb->snd_una = tcb->snd_nxt;

	// RST 并不消耗序列号
	rc = tcp_transmit_skb(&tsk->sk, skb, tcb->snd_nxt);
	free_skb(skb);
	return rc;
}

int
tcp_send_challenge_ack(struct sock *sk, struct sk_buff *skb)
{
	// todo;
	return 0;
}

int 
tcp_queue_fin(struct sock *sk)
{
	struct sk_buff *skb;
	struct tcphdr *th;
	struct tcb *tcb = &tcp_sk(sk)->tcb;
	int rc = 0;

	skb = tcp_alloc_skb(0, 0);  /* 需要重新分配数据块,不包含tcp选项,不包含数据 */
	th = tcp_hdr(skb);

	th->fin = 1;
	th->ack = 1;

	tcp_sock_dbg("Queueing fin", sk);
	rc = tcp_queue_transmit_skb(sk, skb);
	/* TCP规定,FIN报文即使不携带数据,它也要消耗掉一个序号 */
	tcb->snd_nxt++;	/* FIN消耗一个序列号 */

	return rc;
}