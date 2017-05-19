#ifndef ARP_H
#define ARP_H
#include "syshead.h"
#include "ethernet.h"
#include "netdev.h"
#include "skbuff.h"
#include "list.h"
#include "utils.h"

#define ARP_ETHERNET	0x0001
#define ARP_IPV4		0x0800
#define ARP_REQUEST		0x0001
#define ARP_REPLY		0x0002

#define ARP_HDR_LEN	sizeof(struct arp_hdr)
#define ARP_DATA_LEN sizeof(struct arp_ipv4)

#define ARP_CACHE_LEN	32
//
// ARP请求的操作字段一共有4种操作类型.ARP请求(1), ARP应答(2)
// RARP请求(3)和RARP应答(4),RARP协议基本上被废弃了.
// 
#define ARP_FREE		0			
#define ARP_WAITING		1
#define ARP_RESOLVED	2


#ifdef DEBUG_ARP
#define arp_dbg(str, hdr)                                               \
    do {                                                                \
        print_debug("arp "str" (hwtype: %hu, protype: %.4hx, "          \
                    "hwsize: %d, prosize: %d, opcode: %.4hx)",         \
                    hdr->hwtype, hdr->protype, hdr->hwsize,             \
                    hdr->prosize, hdr->opcode);                         \
    } while (0)

#define arpdata_dbg(str, data)															\
    do {																				\
        print_debug("arp data "str" (smac: %.2hhx:%.2hhx:%.2hhx:%.2hhx"					\
                    ":%.2hhx:%.2hhx, sip: %hhu.%hhu.%hhu.%hhu, dmac: %.2hhx:%.2hhx"		\
                    ":%.2hhx:%.2hhx:%.2hhx:%.2hhx, dip: %hhu.%hhu.%hhu.%hhu)",			\
                    data->smac[0], data->smac[1], data->smac[2], data->smac[3],			\
                    data->smac[4], data->smac[5], data->sip >> 24, data->sip >> 16,		\
                    data->sip >> 8, data->sip >> 0, data->dmac[0], data->dmac[1],		\
                    data->dmac[2], data->dmac[3], data->dmac[4], data->dmac[5],			\
                    data->dip >> 24, data->dip >> 16, data->dip >> 8, data->dip >> 0);	\
    } while (0)

#define arpcache_dbg(str, entry)														\
    do {																				\
    print_debug("arp cache "str" (hwtype: %hu, sip: %hhu.%hhu.%hhu.%hhu, "				\
    "smac: %.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx, state: %d)", entry->hwtype,		\
        entry->sip >> 24, entry->sip >> 16, entry->sip >> 8, entry->sip >> 0,			\
        entry->smac[0], entry->smac[1], entry->smac[2], entry->smac[3], entry->smac[4], \
                entry->smac[5], entry->state);											\
    } while (0)
#else
#define arp_dbg(str, hdr)
#define arpdata_dbg(str, data)
#define arpcache_dbg(str, entry)
#endif

// ARP 头部
struct arp_hdr
{
	uint16_t hwtype;		// 硬件类型
	uint16_t protype;		// 协议类型
	uint8_t hwsize;			// 硬件地址长度
	uint8_t prosize;		// 协议地址长度
	uint16_t opcode;		// 操作类型
	unsigned char data[];
} __attribute__((packed));

// ARP请求和应答分组的数据部分
struct arp_ipv4
{
	unsigned char smac[6];  // 发送端以太网地址
	uint32_t sip;			// 发送端ip地址
	unsigned char dmac[6];  // 目的以太网地址
	uint32_t dip;			// 目的ip地址
} __attribute__((packed));

// arp_cache_entry 用于表示arp缓存
struct arp_cache_entry
{
	struct list_head list;
	uint16_t hwtype;
	uint32_t sip;
	unsigned char smac[6];
	unsigned int state;
};

unsigned char* arp_get_hwaddr(uint32_t sip);
void arp_init();
void free_arp();
void arp_rcv(struct sk_buff *skb);
void arp_reply(struct sk_buff *skb, struct netdev *netdev);
int arp_request(uint32_t sip, uint32_t dip, struct netdev *netdev);


// arp_hdr用于获取从以太网帧中获取arp头部,以太网头部之后立马就是arp协议的头部
static inline struct arp_hdr *
arp_hdr(struct sk_buff *skb)
{
	return (struct arp_hdr *)(skb->head + ETH_HDR_LEN);
}

#endif // !ARP_H_