#ifndef TCP_DATA_H
#define TCP_DATA_H

#include "tcp.h"
int tcp_data_dequeue(struct tcp_sock *tsk, void *user_buf, int len);
int tcp_data_queue(struct tcp_sock *tsk, struct tcphdr *th, struct sk_buff *skb);
int tcp_data_close(struct tcp_sck *tsk, struct tcphdr *th, struct sk_buff *skb);

#endif // !TCP_DATA_H