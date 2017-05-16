#include "syshead.h"
#include "netdev.h"
#include "tuntap.h"
#include "route.h"
#include "ipc.h"
#include "timer.h"
#include "tcp.h"
#include "TEST.h"
#include "tcp.h"
#include "arp.h"
#include "checksum.h"

extern struct netdev* netdev;

// 计算校验和
uint16_t 
in_checksum(const void* buf, int len)
{
	assert(len % 2 == 0);
	const uint16_t* data = (const uint16_t*)buf;
	int sum = 0;
	for (int i = 0; i < len; i += 2)
	{
		sum += *data++;
	}
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	assert(sum <= 0xFFFF);
	return ~sum;
}


// TEST_TCP_CHECKSUM 测试tcp检验和是否正确
void 
TEST_TCP_CHECKSUM()
{
	// 下面检验发送ack
	int len = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
	struct sk_buff *skb = alloc_skb(len); // 不包含tcp选项和数据
	skb_reserve(skb, len);  // 将skb的data指针指向尾部
	skb->dlen = 0;  // 实际的数据大小为0

	struct tcphdr *thdr = tcp_hdr(skb); // 指向tcp头部
	thdr->ack = 1;
	thdr->hl = TCP_DOFFSET;
	skb_push(skb, thdr->hl * 4); // 将skb的data指针后退tcp头部大小个字节

	// 端口随便填入
	thdr->sport = htons(1000);
	thdr->dport = htons(80);
	thdr->seq = htonl(12345678);  /* 序列号 */
	thdr->ack_seq = htonl(0);    /* 仅当ack标志有效时这个东西才有效 */
	thdr->win = htons(1500);
	thdr->urp = htons(0);		/* 仅当urg标志有效时才有用 */
	thdr->csum = 0;

	// 接下来计算检验和
	thdr->csum = tcp_v4_checksum(skb, ip_pton("10.0.1.4"), ip_pton("10.0.1.5"));
	printf("checksum = 0x%llX\n", thdr->csum);
	// 下面开始第二轮检验
	thdr->csum = 0;
	int tcp_len = skb->len;
	//skb_push(skb, sizeof(struct tcp_fake_head));
	/*
	struct tcp_fake_head* fk_hdr = (struct tcp_fake_head*)skb->data;
	fk_hdr->src = ip_pton("10.0.1.4");
	fk_hdr->dst = ip_pton("10.0.1.5");
	fk_hdr->zero = 0;
	fk_hdr->protocol = htons(IP_TCP);	
	fk_hdr->tcp_len = htons(tcp_len);
	uint16_t csum = in_cksum(skb->data, skb->len);
	*/
	//printf("checksum = 0x%llX\n", csum);
}

// TEST_SEND_ARP 测试ARP
void 
TEST_SEND_ARP()
{
	arp_request(parse_ipv4_string("10.0.1.4"), parse_ipv4_string("10.0.1.5"), netdev);
}
