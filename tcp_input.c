#include "syshead.h"
#include "tcp.h"
#include "skbuff.h"
#include "sock.h"

static int
tcp_clean_rto_queue(struct sock *sk, uint32_t una)
{
	struct tcp_sock *tsk = tcp_sk(sk);
	struct sk_buff *skb;
	int rc = 0;

	pthread_mutex_lock(&sk->write_queue.lock);
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
		tcp_stop_rto_timer(tsk);
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

	tcp_free(sk);
}

/* tcp_drop 用于丢弃数据报. */
static inline int
tcp_drop(struct tcp_sock *tsk, struct sk_buff *skb)
{
	free_skb(skb);
	return 0;
}

static int
tcp_verify_segment(struct tcp_sock *tsk, struct tcphdr *th, struct sk_buff *skb)
{
	struct tcb *tcb = &tsk->tcb;

	if (skb->dlen > 0 && tcb->rcv_wnd == 0) return 0;
	/* 接收到的包的序列号如果小于我们期待接收的下一个数据报的序列号(rcv_nxt),那么这个数据包可能是
	 * 重传的,同时,如果序列号大于rcv_nxt+rcv_wnd,表示可能是对方传送太多,当然也可能是别的原因.
	 * 总之这些都是无用的数据报. */
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

static int 
tcp_listen(struct tcp_sock *tsk, struct sk_buff *skb, struct tcphdr *th)
{
	free_skb(skb);
	return 0;
}


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

	if (th->rst) { /* 此端给彼端发送了一个syn,然后对方发过来一个rst */
		tcp_reset(&tsk->sk);
		goto discard;
	}

	if (!th->syn) { 
		goto discard;
	}

	tcb->rcv_nxt = th->seq + 1;  /* tcb->rcv_nxt表示期待接收到的序号 */
	tcb->irs = th->seq;			 /* tcb->irs表示数据发送的初始序列号(initial receive sequence number) */

	if (th->ack) {  /* 对方确认了syn */
		tcb->snd_una = th->ack_seq; /* una表示尚未确认的序列号 */
		/* 可以将已经确认了的数据丢弃掉了 */
		tcp_clean_rto_queue(sk, tcb->snd_una);
	}

	/* tcb->snd_una表示未经确认的序列号, isn表示第一次发送syn是采用的序列号
	  一般来说,未经确认的序列号不会小于isn */
	if (tcb->snd_una > tcb->isn) { /* 作为客户端,接收到了服务端发送的syn, ack */
		tcp_set_state(sk, TCP_ESTABLISHED); /* 连接建立成功 */
		tcb->snd_una = tcb->snd_nxt; /* snd_nxt表示发送数据时下一个要采用的序列号 */
		tcp_send_ack(&tsk->sk);  /* 发送ack,第3次握手 */
		sock_connected(sk);
	}
	else { /* 作为服务器端,接收到了客户端发送的syn */
		/* 发送syn以及ack,进入syn_received状态 */
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
tcp_input_state(struct sock *sk, struct tcphdr *th, struct sk_buff *skb)
{
	struct tcp_sock *tsk = tcp_sk(sk); 
	struct tcb *tcb = &tsk->tcb; /* transmission control block 传输控制块 */

	tcp_sock_dbg("input state", sk);

	switch (sk->state) {
	case TCP_CLOSE:   /* 处于close状态,接收到了tcp数据报 */
		return tcp_closed(tsk, skb, th);
	case TCP_LISTEN:  /* 处于listen状态 */
		return tcp_listen(tsk, skb, th);
	case TCP_SYN_SENT: /* 已经主动发送了一个syn */
		return tcp_synsent(tsk, skb, th);
	}
	/* 1.检查sequence number */
	if (!tcp_verify_segment(tsk, th, skb)) {
		if (!th->rst) {
			tcp_send_ack(sk);
		}
		return tcp_drop(tsk, skb);
	}

	/* 2.检查rst bit */
	if (th->rst) {
		/*
		 只要接收到了RST标记,连接立即复位,进入TIME_WAIT状态.
		 */
		free_skb(skb);
		tcp_enter_time_wait(sk);
		/* recv_notify主要用于唤醒调用socket的程序 */
		tsk->sk.ops->recv_notify(&tsk->sk);
		return 0;
	}

	/* 3.检查安全性和优先级
	   待实现
	 */
	
	/* 4.检查syn bit */
	if (th->syn) {
		/* syn一般只在两处地方见到,第一是主动发起连接,第二是对方主动连接过来,这里是第二种情况. */
		tcp_send_challenge_ack(sk, skb);
		return tcp_drop(tsk, skb);
	}

	if (!th->ack) {
		return tcp_drop(tsk, skb);
	}

	/* 运行到了这里,接收的数据无syn,有ack
	   这是什么情况呢? 这是正常的情况,表明连接的两方在正常地交换数据. */
	switch (sk->state) {
	case TCP_SYN_RECEIVED: /* 作为服务端,接收到了客户端发送的ack和syn */
		if (tcb->snd_una <= th->ack_seq && th->ack_seq < tcb->snd_nxt) {
			tcp_set_state(sk, TCP_ESTABLISHED);	
		}
		else {
			return tcp_drop(tsk, skb);
		}
	case TCP_ESTABLISHED:
	case TCP_FIN_WAIT_1:	/* 主动关闭 */
	case TCP_FIN_WAIT_2:	/* FIN_WAIT_2状态依旧可以接收对方发送的数据,直到对方发送了FIN,然后进入TIME_WAIT状态 */
	case TCP_CLOSE_WAIT:	/* 接收到了FIN,执行被动关闭 */
	case TCP_CLOSING:		/* 两端同时关闭,会进入closing状态 */
	case TCP_LAST_ACK:
		/* ack_seq确认了已经发送的一部分数据(> snd_una即未确认的序号的开始) */
		if (tcb->snd_una < th->ack_seq && th->ack_seq <= tcb->snd_nxt) {
			/* 这里表示已经收到了对方的确认,首先要明白一点,确认不一定按序到达 */
            tcb->snd_una = th->ack_seq;
			tcp_clean_rto_queue(sk, tcb->snd_una); 
		}
		/* ack_seq < snd_una 多半是出现了重发 */
		if (th->ack_seq < tcb->snd_una) {
			return tcp_drop(tsk, skb);
		}
		/* ack_seq > snd_nxt 这基本上不可能 */
		if (th->ack_seq > tcb->snd_nxt) {
			return tcp_drop(tsk, skb);
		}
		/* snd_una表示最小的未被确认的序列号 */
		if (tcb->snd_una < th->ack_seq && th->ack_seq <= tcb->snd_nxt) {
			// todo: 发送窗口需要被更新
		}
		break;
	}

	/* 如果写队列为空,标志着FIN被确认了 */
	if (skb_queue_empty(&sk->write_queue)) {
        switch (sk->state) {
        case TCP_FIN_WAIT_1:
            tcp_set_state(sk, TCP_FIN_WAIT_2);
        case TCP_FIN_WAIT_2:
            break;
        case TCP_CLOSING:
            /* In addition to the processing for the ESTABLISHED state, if
             * the ACK acknowledges our FIN then enter the TIME-WAIT state,
               otherwise ignore the segment. */
            tcp_set_state(sk, TCP_TIME_WAIT);
            break;
        case TCP_LAST_ACK:
            /* The only thing that can arrive in this state is an acknowledgment of our FIN.  
             * If our FIN is now acknowledged, delete the TCB, enter the CLOSED state, and return. */
            free_skb(skb);
            return tcp_done(sk);
        case TCP_TIME_WAIT:
            /* TODO: The only thing that can arrive in this state is a
               retransmission of the remote FIN.  Acknowledge it, and restart
               the 2 MSL timeout. */
            if (tcb->rcv_nxt == th->seq) {
                tcp_sock_dbg("Remote FIN retransmitted?", sk);
//                tcb->rcv_nxt += 1;
                tsk->flags |= TCP_FIN;
                tcp_send_ack(sk);
            }
            break;
        }
    }
    
    /* 6.检查URG bit */
    if (th->urg) {

	}

	pthread_mutex_lock(&sk->receive_queue.lock);

	switch (sk->state) {
	case TCP_ESTABLISHED:
	case TCP_FIN_WAIT_1:
	case TCP_FIN_WAIT_2:
		tcp_data_queue(tsk, th, skb);
		tsk->sk.ops->recv_notify(&tsk->sk);	/* 唤醒上层正在等待数据的进程 */
		break;
	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
	case TCP_LAST_ACK:
	case TCP_TIME_WAIT:
		/* 不应该运行到这里,因为才能够remote side接收到了一个FIN */
		break;
	}

	/* 8, 检查fin
	  rcv_nxt是下一个期望收到的数据的序列号, skb->seq是这个数据报的起始编号
	  第2个条件是保证,在FIN之前的数据全部接收成功了. */
	if (th->fin && (tcb->rcv_nxt - skb->dlen) == skb->seq) {
		tcp_sock_dbg("Received in-sequence FIN", sk);

        switch (sk->state) {
        case TCP_CLOSE:
        case TCP_LISTEN:
        case TCP_SYN_SENT:
            // Do not process, since SEG.SEQ cannot be validated
            goto drop_and_unlock;
        }

		tcb->rcv_nxt += 1;
		tsk->flags |= TCP_FIN;
		tcp_send_ack(sk);
		tsk->sk.ops->recv_notify(&tsk->sk);

		switch (sk->state) {
		case TCP_SYN_RECEIVED:
		case TCP_ESTABLISHED:  /* CLOSE_WAIT 被动关闭 */
			tcp_set_state(sk, TCP_CLOSE_WAIT);
			break;
		case TCP_FIN_WAIT_1:
			if (skb_queue_empty(&sk->write_queue)) {
				tcp_enter_time_wait(sk);
			}
			else {
				tcp_set_state(sk, TCP_CLOSING);
			}
			break;
		case TCP_FIN_WAIT_2: /* FIN_WAIT_2接收到FIN之后,进入TIME_WAIT状态,基本上一个tcp连接就完成了. */
			tcp_enter_time_wait(sk);
			break;
		case TCP_CLOSE_WAIT:
		case TCP_CLOSING:
		case TCP_LAST_ACK:
			break;
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

		if (sock->flags & O_NONBLOCK) { 
			if (rlen == 0) { 
				rlen = -EAGAIN;  /* 立马返回 */
			}
			break;
		}
		else {
			wait_sleep(&tsk->sk.recv_wait);
		}
	}
	return rlen;
}