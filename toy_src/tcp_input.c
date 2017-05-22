#include "syshead.h"
#include "tcp.h"
#include "skbuff.h"
#include "sock.h"

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

static int
tcp_synrecv_ack(struct tcp_sock *tsk)
{
	if (tsk->parent->sk.state != TCP_LISTEN) return -1;
	tcp_accept_enqueue(tsk);
	wait_wakeup(&tsk->parent->wait);
	return 0;
}

/* tcp_clean_retransmission_queue对sk的重传队列进行清理,即将接收到了确认的数据丢弃 */
static int
tcp_clean_retransmission_queue(struct sock *sk, uint32_t una)
{
	struct tcp_sock *tsk = tcp_sk(sk);
	struct sk_buff *skb;
	int rc = 0;

	pthread_mutex_lock(&sk->write_queue.lock);
	/* 需要注意的是,在write_queue中的数据是严格按照发送顺序排列的. 
	 所以write_queue中skb的end_seq升序排列 */
	while ((skb = skb_peek(&sk->write_queue)) != NULL) {
		/* 释放掉已经接收到了确认的数据 */
		if (skb->end_seq <= una) {
			skb_dequeue(&sk->write_queue);
			skb->refcnt--;
			free_skb(skb);
		}
		else {
			break;
		}
	}

	/* skb == NULL表示要发送的数据全部发送完毕,并且都接收到了确认,也就是发送成功 */
	if (skb == NULL) {
		tcp_stop_retransmission_timer(tsk);
	}

	pthread_mutex_unlock(&sk->write_queue.lock);
	return rc;
}

static void
tcp_reset(struct sock *sk) {
	switch (sk->state) {
	case TCP_SYN_SENT:
		sk->err = -ECONNREFUSED;	/* 连接失败 */
		break;
	/* 此端接收到对端的发送的FIN,进入CLOSE_WAIT状态,此时对方不应该再发送tcp数据,
	 因为发送的FIN表示关闭写的管道.向已经关闭的管道写数据,会导致管道破裂(EPIPE)错误. */
	case TCP_CLOSE_WAIT: 
		sk->err = -EPIPE;			
		break;
	case TCP_CLOSE:
		return;
	default:
		sk->err = -ECONNRESET;
		break;
	}

	tcp_free_sock(sk);
}

/* tcp_drop 用于丢弃数据报. */
static inline int
tcp_drop(struct tcp_sock *tsk, struct sk_buff *skb)
{
	free_skb(skb);
	return 0;
}

static int
tcp_packet_filter(struct tcp_sock *tsk, struct tcphdr *th, struct sk_buff *skb)
{
	struct tcb *tcb = &tsk->tcb;

	if (skb->dlen > 0 && tcb->rcv_wnd == 0) return 0;
	/* 接收到的包的序列号如果小于我们期待接收的下一个数据报的序列号(rcv_nxt),那么这是一个
	重传的数据包,同时,如果序列号大于rcv_nxt+rcv_wnd,表示可能是对方传送太多,当然也可能
	是别的原因.总之这些都是无用的数据报. */
	if (th->seq < tcb->rcv_nxt ||
		th->seq > (tcb->rcv_nxt + tcb->rcv_wnd)) {
		tcp_sock_dbg("Received invalid segment", (&tsk->sk));
		return 0;
	}

	return 1;
}

static inline int 
tcp_discard(struct tcp_sock *tsk, struct sk_buff *skb, struct tcphdr *th)
{
	free_skb(skb);
	return 0;
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

static struct tcp_sock *
tcp_listen_child_sock(struct tcp_sock *tsk, struct tcphdr *thr, struct iphdr * ih)
{
	struct sock *newsk = tcp_alloc_sock();
	struct tcp_sock *newtsk = tcp_sk(newsk);
	newsk->saddr = ih->daddr;
	newsk->daddr = ih->saddr;
	newsk->sport = thr->dport;
	newsk->dport = thr->sport;

	newtsk->parent = tsk;
	list_add(&newtsk->list, &tsk->listen_queue);	/* 将新的sock加入监听队列 */
	return newtsk;
}

/* tcp_listen用于监听 */
static int 
tcp_handle_listen(struct tcp_sock *tsk, struct sk_buff *skb, struct tcphdr *th)
{
	/* tcp规定,syn报文段不能携带数据,但是要消耗掉一个序号 */
	struct tcp_sock *newtsk;
	struct iphdr *iphdr = ip_hdr(skb);
	
	/* 1. 检查rst */
	if (th->rst) goto discard;

	/* 2. 检查ack */
	if (th->ack) {
		tcp_send_reset(tsk);
		goto discard;
	}

	/* 3. 检查syn */
	if (!th->syn) goto discard;

	newtsk = tcp_listen_child_sock(tsk, th, iphdr);
	/* 构建了一个新的sock之后,需要将该sock放入队列中 */
	if (!newtsk) goto discard;
	tcp_set_state((&newtsk->sk), TCP_SYN_RECEIVED);

	struct tcb *tc = &newtsk->tcb;
	/* 准备向对方发送ack以及syn */
	tc->irs = th->seq;
	tc->isn = generate_isn();
	tc->snd_nxt = tc->isn;		/* 发送给对端的seq序号 */
	tc->rcv_nxt = th->seq + 1;	/* 发送给对端的ack序号, 对方发送的syn消耗掉一个序号 */
	tcp_send_synack(&newtsk->sk);
	tcp_established_or_syn_recvd_socks_enqueue(&newtsk->sk);
	tc->snd_nxt = tc->isn + 1;	/* syn消耗掉一个序号 */
	tc->snd_una = tc->isn;
discard:
	free_skb(skb);
	return 0;
}


/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

static int
tcp_synsent(struct tcp_sock *tsk, struct sk_buff *skb, struct tcphdr *th)
{
	struct tcb *tcb = &tsk->tcb;
	struct sock *sk = &tsk->sk;

	tcp_sock_dbg("state is synsent", sk);

	if (th->ack) {
		/* th->ack_seq < tcb->isn 以及 th->ack_seq > tcb->snd_nxt
		   根据tcp协议栈的话,都是不可能的. */
		if (th->ack_seq < tcb->isn || th->ack_seq > tcb->snd_nxt) {
			tcp_sock_dbg("ACK is unacceptable", sk);
			if (th->rst) goto discard;
			goto reset_and_discard;
		}
		
		if (th->ack_seq < tcb->snd_una || th->ack_seq > tcb->snd_nxt) {
			tcp_sock_dbg("ACK is unacceptable", sk);
			goto reset_and_discard;
		}
	}

	/* 我们给对方发送了一个syn,试图连接对方,然后对方发过来一个rst */
	if (th->rst) { 
		// tofix: 接收到rst,应该断开连接
		goto discard;
	}

	if (!th->syn) goto discard;

	tcb->rcv_nxt = th->seq + 1;  /* tcb->rcv_nxt表示期待接收到的序号 */
	tcb->irs = th->seq;			 /* tcb->irs表示数据发送的初始序列号(initial receive sequence number) */

	if (th->ack) {  /* 对方确认了syn */
		tcb->snd_una = th->ack_seq; /* una表示尚未确认的序列号 */
		/* 可以将syn数据报从write queue中移除了 */
		tcp_clean_retransmission_queue(sk, tcb->snd_una);
	}

	/* 一般来说,未经确认的序列号不会小于isn */
	if (tcb->snd_una > tcb->isn) { /* 作为客户端,接收到了服务端发送的syn, ack */
		tcp_set_state(sk, TCP_ESTABLISHED); /* 连接建立成功 */
		tcb->snd_una = tcb->snd_nxt; /* snd_nxt表示发送数据时下一个要采用的序列号 */
		tcp_send_ack(&tsk->sk);  /* 发送ack,第3次握手 */
		wait_wakeup(&tsk->wait);
	}
	else {
		/* 这里对应着一种概率特小的事件,那就是两边同时试图连接对方,也就是同时打开的情况.
		 这里两端都进入syn_received状态,一旦对方接收到发送的syn和ack,直接进入established
		 状态.*/
		tcp_set_state(sk, TCP_SYN_RECEIVED);
		tcb->snd_una = tcb->isn;
		tcp_send_synack(&tsk->sk); /* 第2次握手 */
	}

discard:
	tcp_drop(tsk, skb);
    return 0;
reset_and_discard:
	/* todo: reset */
	tcp_drop(tsk, skb);
	return 0;
}

static int 
tcp_closed(struct tcp_sock *tsk, struct sk_buff *skb, struct tcphdr *th)
{
	/* 所有incoming segment(传送过来的数据报)中的数据都会被丢弃掉.如果数据报包含
	   rst, 直接丢弃,如果不包含,我们要发送一个带rst的数据报作为回应. */
	int rc = -1;
	
	tcp_sock_dbg("state is closed", (&tsk->sk));

	if (th->rst) {  
		tcp_discard(tsk, skb, th);
		rc = 0;
		goto out;
	}

	/* todo */
	if (th->ack) {

	}
	else {

	}

	rc = tcp_send_reset(tsk);
	free_skb(skb);
out:
	return rc;
}

int
tcp_process(struct sock *sk, struct tcphdr *th, struct sk_buff *skb)
{
	struct tcp_sock *tsk = tcp_sk(sk); 
	struct tcb *tcb = &tsk->tcb; /* transmission control block 传输控制块 */

	tcp_sock_dbg("input state", sk);

	switch (sk->state) {
	case TCP_CLOSE:   /* 处于close状态,接收到了tcp数据报 */
		return tcp_closed(tsk, skb, th);
	case TCP_LISTEN:  /* 处于listen状态 */
		return tcp_handle_listen(tsk, skb, th);
	case TCP_SYN_SENT: /* 已经主动发送了一个syn */
		return tcp_synsent(tsk, skb, th);
	}

	/* 1.检查sequence number, tcp_packet_filter是第一层过滤器,携带了tcp数据的包
	 能够通过,其余的比如syn,fin等不携带数据的包,首先,要过滤掉重传的部分.
	 */
	if (!tcp_packet_filter(tsk, th, skb)) {
		if (!th->rst) {
			tcp_send_ack(sk);	/* 告诉对方,我接收到了这个数据包 */
		}
		return tcp_drop(tsk, skb);
	}

	/* 2.检查rst bit */
	

	/* 3.检查安全性和优先级 */
	
	/* 4.检查syn */
	if (th->syn) {
		/* 仅listen和syn_sent两个状态可以接收syn,而事实上,这两个状态在上面已经处理过了,
		 所以运行到这里,表示sk一定不处于这两个状态,此外,还需要注意一点:
		 重传的syn数据包在前面已经被丢弃了.所以在这里,这个数据包是错误的. */
		tcp_send_reset(tsk);
		if (sk->state == TCP_SYN_RECEIVED && tsk->parent) {
			/*此时tsk一定被挂在tcp_established_or_syn_recvd_socks链表上,所以要从
			 链表中删除该sock */
			tcp_established_or_syn_recvd_socks_remove(sk);
			tcp_free_sock(sk);
		}
	}

	/* 5.检查ack */
	if (!th->ack) return tcp_drop(tsk, skb);

	/* 运行到了这里,接收的数据无syn,有ack
	   这是什么情况呢? 这是正常的情况,表明连接的两方在正常地交换数据. */
	switch (sk->state) {
	case TCP_SYN_RECEIVED:
		/* 作为服务端,接收到了对方发送的ack,连接成功建立 */
		if (tcb->snd_una <= th->ack_seq && th->ack_seq <= tcb->snd_nxt) {
			if (tcp_synrecv_ack(tsk) < 0) {
				return tcp_drop(tsk, skb);
			}
			tcb->snd_una = th->ack_seq;
			tcp_set_state(sk, TCP_ESTABLISHED);	
		}
		else {
			tcp_send_reset(tsk);
			return tcp_drop(tsk, skb);
		}
		break;
	case TCP_ESTABLISHED:
	case TCP_FIN_WAIT_1:	/* 主动关闭 */
	case TCP_FIN_WAIT_2:	/* fin_wait_2状态依旧可以接收对方发送的数据,直到对方发送了fin,然后进入time_wait状态 */
	case TCP_CLOSE_WAIT:	/* 接收到了FIN,执行被动关闭 */
	case TCP_CLOSING:		/* 两端同时关闭,会进入closing状态 */
	case TCP_LAST_ACK:
		/* 下面的条件判断是我们对tcp数据包的第二次过滤,这里主要是过滤掉携带tcp数据的重传
		 数据,过滤掉序列号不正常的tcp数据包 */

		/* 下面是确保对方发过来的ack_seq是对我们发给对方的并且还没有接收到确认的数据的确认 */
		if (tcb->snd_una < th->ack_seq && th->ack_seq <= tcb->snd_nxt) {
			/* 这里表示对方已经收到了我们的数据包,ack_seq是下次期望的顺序号,一旦接收到ack
			 表示ack_seq序号之前的数据都已经收到了. */
            tcb->snd_una = th->ack_seq;
			tcp_clean_retransmission_queue(sk, tcb->snd_una); 
		}
		
		if (th->ack_seq > tcb->snd_nxt) return tcp_drop(tsk, skb);
		if (th->ack_seq < tcb->snd_una) return tcp_drop(tsk, skb);
		/* ack_seq < snd_una 多半是出现了对已经发送数据的二次确认,直接丢弃即可,
		   ack_seq > snd_nxt 这基本上不可能 */
		break;
	}
    
    /* 6.检查URG bit */
	


	/* 7. segment text */
	pthread_mutex_lock(&sk->receive_queue.lock);
	switch (sk->state) {
	case TCP_ESTABLISHED:
	case TCP_FIN_WAIT_1:
	case TCP_FIN_WAIT_2:
		if (skb->dlen > 0) {	/* 有数据传递过来 */
			tcp_data_queue(tsk, th, skb);
			tsk->sk.ops->recv_notify(&tsk->sk);	/* 唤醒上层正在等待数据的进程 */
		}
		break;
	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
	case TCP_LAST_ACK:
	case TCP_TIME_WAIT:
		/* close_wait, closing, last_ack, time_wait这几个状态都有一个共同点,那就是
		 我们已经接收到了对方发送的fin,这意味着对方声明不会再发送数据(tcp数据)过来,如果发送
		 了,我们完全忽略即可.*/
		break;
	}

	/* 8, 检查fin */
	 /* 第2个条件是保证,在fin之前的数据全部接收成功了. */
	if (th->fin && (tcb->rcv_nxt - skb->dlen) == skb->seq) {
		tcp_sock_dbg("Received in-sequence FIN", sk);
        switch (sk->state) {
        case TCP_CLOSE:
        case TCP_LISTEN:
        case TCP_SYN_SENT:
            goto drop_and_unlock;
        }

		tcb->rcv_nxt += 1;	/* fin需要消耗掉一个序号 */
		tsk->flags |= TCP_FIN;
		tcp_send_ack(sk);
		tsk->sk.ops->recv_notify(&tsk->sk);

		switch (sk->state) {
		case TCP_SYN_RECEIVED:
		case TCP_ESTABLISHED:  /* close_wait 被动关闭 */
			tcp_set_state(sk, TCP_CLOSE_WAIT);
			tsk->sk.ops->recv_notify(&tsk->sk);
			break;
		case TCP_FIN_WAIT_1:
			/* 两端同时发送fin,进入closing状态 */
			tcp_set_state(sk, TCP_CLOSING);
			break;
		case TCP_FIN_WAIT_2: /* fin_wait_2接收到fin之后,进入time_wait状态,
							 基本上一个tcp连接就完成了. */
			tcp_enter_time_wait(sk);
			break;
		case TCP_CLOSE_WAIT:
		case TCP_CLOSING:
		case TCP_LAST_ACK:
		case TCP_TIME_WAIT:
			break;
		}

	}
	free_skb(skb);
unlock:
	pthread_mutex_unlock(&sk->receive_queue.lock);
	return 0;
drop_and_unlock:
	tcp_drop(tsk, skb);
	goto unlock;
}

int
tcp_receive(struct tcp_sock *tsk, void *buf, int len)
{
	int rlen = 0;		/* rlen表示已经读过的数据 */
	int curlen = 0;
	struct sock *sk = &tsk->sk;
	struct socket *sock = sk->sock;
	memset(buf, 0, len);
	
	/* 接收tcp数据报的原则在于,尽量将buf填满,除非已经读到了FIN */
	while (rlen < len) {
		curlen = tcp_data_dequeue(tsk, buf + rlen, len - rlen);
		rlen += curlen;

		if (tsk->flags & TCP_PSH) {
			tsk->flags &= ~TCP_PSH;
			break;
		}

		/* 读取到了结尾 */
		if (tsk->flags & TCP_FIN || rlen == len) break;

		wait_sleep(&sk->recv_wait);
	}
	return rlen;
}

