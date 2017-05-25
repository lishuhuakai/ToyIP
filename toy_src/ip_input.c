#include "ip.h"
#include "syshead.h"
#include "arp.h"
#include "tcp.h"
#include "udp.h"
#include "icmpv4.h"
//
// ip_input.c 主要用于接收ip数据包.
// 

// ip_init_pkt对于接收到的ip数据报进行一定程度的解码,也就是将网络字节序转换为主机字节序
// 方便后面的操作.
static void
ip_init_pkt(struct iphdr *ih)
{
	ih->saddr = ntohl(ih->saddr);	/* 源ip地址 */
	ih->daddr = ntohl(ih->daddr);	/* 目的ip地址 */
	ih->len = ntohs(ih->len);		/* 16位总长度 */
	ih->id = ntohs(ih->id);			/* 唯一的标识 */
}


/**\
 * ip_pkt_for_us 判断数据包是否是传递给我们的.
\**/
static int
ip_pkt_for_us(struct iphdr *ih)
{
	extern char * stackaddr;
	return ih->daddr == ip_parse(stackaddr) ? 1 : 0;
}

int
ip_rcv(struct sk_buff *skb)
{
	struct iphdr *ih = ip_hdr(skb);
	uint16_t csum = -1;


	if (ih->version != IPV4) { // 0x0800 IPv4
		print_err("Datagram version was not IPv4\n");
		goto drop_pkt;
	}

	if (ih->ihl < 5) {
		// 5 * 32bit = 20字节
        print_err("IPv4 header length must be at least 5\n");
		goto drop_pkt;
	}

	if (ih->ttl == 0) {
		print_err("Time to live of datagram reached 0\n");
		goto drop_pkt;
	}

	csum = checksum(ih, ih->ihl * 4, 0);

	if (csum != 0) {
		/* 无效的数据报 */
		goto drop_pkt;
	}

	/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	  todo: ip数据报重组
	  ip协议并不是一个可靠的协议,它没有tcp协议的重传和确认机制.
	  当上层应用数据报过大,超过了MTU,那么在ip层就要进行拆包,将
	  大数据拆分成小数据发送出去,对方接收到之后也要进行组包.
	 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

	ip_init_pkt(ih);
	ip_dbg("in", ih);

	if (!ip_pkt_for_us(ih)) goto drop_pkt;
    switch (ih->proto) {
    case ICMPV4:
        icmpv4_incoming(skb);
        return 0;
    case IP_TCP:
        tcp_in(skb);
        return 0;
	case IP_UDP:
		udp_in(skb);
		return 0;
    default:
        print_err("Unknown IP header proto\n");
        goto drop_pkt;
    }

drop_pkt:
	free_skb(skb);
	return 0;
}