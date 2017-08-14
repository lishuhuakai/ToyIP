#include "ethernet.h"
#include "icmpv4.h"
#include "utils.h"
#include "ip.h"
#include "sock.h"
#include <sys/time.h>
//
// ICMP -- Internet控制报文协议.
// 
void
icmpv4_incoming(struct sk_buff *skb)
{
	struct iphdr *iphdr = ip_hdr(skb);					   // 获得ip头部
	struct icmp_v4 *icmp = (struct icmp_v4 *)iphdr->data;  // ip头部后紧跟icmp

	// todo: Check csum

	switch (icmp->type)
	{
	case ICMP_V4_ECHO:		// 0x08 ping request
		icmpv4_reply(skb);
		return;
	case ICMP_V4_TSTAMP:
		icmpv4_timestamp(skb);
		return;
	default:
		print_err("ICMPv4 did not match supported types\n");
		goto drop_pkt;
	}
drop_pkt:
	free_skb(skb);
	return;
}

void
icmpv4_reply(struct sk_buff *skb)
{
	struct iphdr *iphdr = ip_hdr(skb);		// 获得ip头部
	struct icmp_v4 *icmp;
	// todo
	struct sock sk;
	memset(&sk, 0, sizeof(struct sock));

	// iphdr->ihl * 4指的是ip头部的大小
	uint16_t icmp_len = iphdr->len - (iphdr->ihl * 4);		// ip数据报的总长度减去ip头部大小,得到icmp数据报的大小
	skb_reserve(skb, ETH_HDR_LEN + IP_HDR_LEN + icmp_len);
	skb_push(skb, icmp_len); // icmp回复的大小

	icmp = (struct icmp_v4 *)skb->data;
	icmp->type = ICMP_V4_REPLY;				   // ICMP回显应答 
	icmp->csum = 0;
	icmp->csum = checksum(icmp, icmp_len, 0);  /* 计算校验和 */

	skb->protocol = ICMPV4;
	sk.daddr = iphdr->saddr;	// 对方发过来的源ip地址变成了目的ip地址

	ip_output(&sk, skb);
	free_skb(skb);
}

void
icmpv4_timestamp(struct sk_buff *skb)
{
	struct iphdr *iphdr = ip_hdr(skb);  // 获得ip头部
	struct icmp_v4_timestamp *icmp;
	struct sock sk;
	struct timeval tv;
	uint32_t ts_recv;
	memset(&sk, 0, sizeof(struct sock));
	uint16_t icmp_len = iphdr->len - (iphdr->ihl << 2);

	skb_reserve(skb, ETH_HDR_LEN + IP_HDR_LEN + icmp_len);
	skb_push(skb, icmp_len);
	icmp = (struct icmp_v4_timestamp *)skb->data;
	
	icmp->type = ICMP_V4_TSTAMP_REPLY;

	gettimeofday(&tv, NULL);
	ts_recv = (tv.tv_sec % (24 * 60 * 60) * 1000 + tv.tv_usec / 1000);
	icmp->rtime = icmp->ttime = htonl(ts_recv);

	icmp->csum = 0;
	icmp->csum = checksum(icmp, icmp_len, 0);
	skb->protocol = ICMPV4;			// 协议不用改变字节序
	sk.daddr = iphdr->saddr;
	ip_output(&sk, skb);
	free_skb(skb);
}