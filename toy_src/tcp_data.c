#include "syshead.h"
#include "tcp.h"
#include "list.h"

/**\
 * tcp_data_insert_ordered 按照序列号的顺序来.
\**/
static void
tcp_data_insert_ordered(struct sk_buff_head *queue, struct sk_buff *skb)
{
	struct sk_buff *next;
	struct list_head *item, *tmp;

	list_for_each_safe(item, tmp, &queue->head) {
        next = list_entry(item, struct sk_buff, list);
		if (skb->seq < next->seq) {
			if (skb->end_seq > next->seq) {
				print_err("Could not join skbs\n");
			}
			else {
				skb->refcnt++;
				skb_queue_add(queue, skb, next);
				return;
			}
		}
		else if (skb->seq == next->seq) {
			/* 这个数据报已经有了 */
			return;
		}
	}
	skb->refcnt++;
	skb_queue_tail(queue, skb);
}

static void
tcp_consume_ofo_queue(struct tcp_sock *tsk)
{
	struct sock *sk = &tsk->sk;
	struct tcb *tcb = &tsk->tcb;
	struct sk_buff *skb = NULL;

	while ((skb = skb_peek(&tsk->ofo_queue)) != NULL &&
		tcb->rcv_nxt == skb->seq) {
		tcb->rcv_nxt += skb->dlen;
		skb_dequeue(&tsk->ofo_queue);			 /* 不断丢弃掉队列里的元素 */
		skb_queue_tail(&sk->receive_queue, skb); /* 添加到尾部 */
	}
}

/**\
 * tcp_data_dequeue 输入队列中的数据出队列.
\**/
int
tcp_data_dequeue(struct tcp_sock *tsk, void *user_buf, int userlen)
{
	struct sock *sk = &tsk->sk;
	struct tcphdr *th;
	struct sk_buff *skb;
	int rlen = 0;
	int dlen;

	pthread_mutex_lock(&sk->receive_queue.lock);	/* 接受队列加锁 */
	while (!skb_queue_empty(&sk->receive_queue) &&
		rlen < userlen) {
		skb = skb_peek(&sk->receive_queue);
		if (skb == NULL) break;
		th = tcp_hdr(skb);
		// tofix: tcp头部可能存在可选项,因此,直接从skb->payload开始拷贝可能存在问题.
		// 当然,如果数据读取的时候,已经将payload指向了数据部分,那就没有问题了. 
		dlen = (rlen + skb->dlen) > userlen ? (userlen - rlen) : skb->dlen;
		memcpy(user_buf, skb->payload, dlen);

		skb->dlen -= dlen;
		skb->payload += dlen;
		rlen += dlen;
		user_buf += dlen;

		if (skb->dlen == 0) { /* 该skb的数据已经全部被取完 */
			if (th->psh) tsk->flags |= TCP_PSH;
			skb_dequeue(&sk->receive_queue);
			skb->refcnt--;
			free_skb(skb);
		}
	}

	pthread_mutex_unlock(&sk->receive_queue.lock);
	return rlen;
}

/**\
 * tcp_data_queue 输入队列中的数据入队列. 
\**/
int
tcp_data_queue(struct tcp_sock *tsk, struct tcphdr *th, struct sk_buff *skb)
{
	struct sock *sk = &tsk->sk;
	struct tcb *tcb = &tsk->tcb;
	int rc = 0;

	if (!tcb->rcv_wnd) {	/* 接受窗口为0的话,丢弃数据 */
		free_skb(skb);
		return -1;
	}

	int expected = skb->seq == tcb->rcv_nxt; 

	if (expected) { /* expected表示tcp数据报是按序到达的 */
		tcb->rcv_nxt += skb->dlen; /* dlen长度的数据被成功确认 */

		skb->refcnt++;
		skb_queue_tail(&sk->receive_queue, skb);  /* 添加到尾部 */
		tcp_consume_ofo_queue(tsk);
		tcp_stop_delack_timer(tsk);

		if (th->psh || (skb->dlen == tsk->rmss && ++tsk->delacks > 1)) {
			tsk->delacks = 0;
			tcp_send_ack(sk);
		}
		else {
			tsk->delack = timer_add(200, &tcp_send_delack, &tsk->sk);
		}
	}
	else {
		tcp_data_insert_ordered(&tsk->ofo_queue, skb);
		tcp_send_ack(sk);
	}
	return rc;
}