#ifndef ICMPV4_H
#define ICMPV4_H

#include "syshead.h"
#include "skbuff.h"

#define ICMP_V4_REPLY				0x00  /* 回显应答 */
#define ICMP_V4_DST_UNREACHABLE		0x03
#define ICMP_V4_SRC_QUENCH			0x04
#define ICMP_V4_REDIRECT			0x05
#define ICMP_V4_ECHO				0x08
#define ICMP_V4_ROUTER_ADV			0x09
#define ICMP_V4_ROUTER_SOL			0x0a
#define ICMP_V4_TIMEOUT				0x0b
#define ICMP_V4_MALFORMED			0x0c
#define ICMP_V4_TSTAMP				0x0d	/* 时间戳请求 */
#define ICMP_V4_TSTAMP_REPLY		0x0e	/* 时间戳应答 */

// icmp报文通用格式
struct icmp_v4 {
	uint8_t type;		// 8位类型
	uint8_t code;		// 8位代码
	uint16_t csum;		// 16位校验和
	uint8_t data[];
} __attribute__((packed));

struct icmp_v4_echo {
	uint16_t id;
	uint16_t seq;
	uint8_t data[];
} __attribute__((packed));

struct icmp_v4_timestamp {
	uint8_t type;
	uint8_t code;
	uint16_t csum;
	uint32_t otime;		/* 发起时间 */
	uint32_t rtime;		/* 接收时间 */
	uint32_t ttime;		/* 传送时间 */
} __attribute__((packed));

struct icmp_v4_dst_unreachable {
	uint8_t unused;
	uint8_t len;
	uint16_t var;
	uint8_t data[];
} __attribute__((packed));

void icmpv4_incoming(struct sk_buff *skb);
void icmpv4_reply(struct sk_buff *skb);
void icmpv4_timestamp(struct sk_buff *skb);
#endif // !ICMPV4_H