#include "syshead.h"
#include "utils.h"
#include "basic.h"
#include "netdev.h"
#include "skbuff.h"
#include "ethernet.h"
#include "ip.h"
#include "tuntap.h"
#include "arp.h"

struct netdev *loop;
struct netdev *netdev;
extern int running;

//
// addr表示ip地址, hwadddr表示mac地址, mtu表示最大传输单元的大小
static struct netdev *
netdev_alloc(char *addr, char* hwaddr, uint32_t mtu)
{
	/* hwaddr表示硬件地址 */
	struct netdev *dev = malloc(sizeof(struct netdev));
	dev->addr = ip_parse(addr);		/* 记录下ip地址 */

	sscanf(hwaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		&dev->hwaddr[0],
		&dev->hwaddr[1],
		&dev->hwaddr[2],
		&dev->hwaddr[3],
		&dev->hwaddr[4],
		&dev->hwaddr[5]);				/* 记录下mac地址 */

	dev->addr_len = 6;					/* 地址长度 */
	dev->mtu = mtu;						/* 最大传输单元 */
	return dev;
}


void 
netdev_init()
{
	loop = netdev_alloc("127.0.0.1", "00:00:00:00:00:00", 1500);
	/* 下面的mac地址是捏造的. */
	netdev = netdev_alloc("10.0.1.4", "00:0c:29:6d:50:25", 1500);
}

/* netdev_transmit 用于对上层传递过来的数据包装以太网头部 */
int 
netdev_transmit(struct sk_buff *skb, uint8_t *dst_hw, uint16_t ethertype)
{
	struct netdev *dev;
	struct eth_hdr *hdr;
	int ret = 0;

	dev = skb->dev;
	skb_push(skb, ETH_HDR_LEN);
	hdr = (struct eth_hdr *)skb->data;

	/* 拷贝硬件地址 */
	memcpy(hdr->dmac, dst_hw, dev->addr_len);
	memcpy(hdr->smac, dev->hwaddr, dev->addr_len);
	
	eth_dbg("out", hdr);
	hdr->ethertype = htons(ethertype);
	/* 回复,直接写即可 */
	ret = tun_write((char *)skb->data, skb->len);
}

static int 
netdev_receive(struct sk_buff *skb)
{
	struct eth_hdr *hdr = eth_hdr(skb);  /* 获得以太网头部信息,以太网头部包括
										 目的mac地址,源mac地址,以及类型信息 */
	eth_dbg("in", hdr);
	/* 以太网头部的Type(类型)字段 0x86dd表示IPv6 0x0800表示IPv4
	0x0806表示ARP */
	switch (hdr->ethertype) {
	case ETH_P_ARP:	/* ARP  0x0806 */
		arp_rcv(skb);
		break;
	case ETH_P_IP:  /* IPv4 0x0800 */
		ip_rcv(skb);
		break;
	case ETH_P_IPV6: /* IPv6 0x86dd -- not supported! */
	default:
		printf("Unsupported ethertype %x\n", hdr->ethertype);
		free_skb(skb);
		break;
	}
	return 0;
}

/* netdev_rx_loop */
void *
netdev_rx_loop()
{
	while (running) {
		struct sk_buff *skb = alloc_skb(BUFLEN);		/* 1600 */
		/* skb是对数据的一个简单封装,真正的数据在skb->data中,skb的其他域是对数据的一些描述 */
		/* tun_read每一次会读取一个数据报,即使该数据长度达不到1600 */
		int len = tun_read((char *)skb->data, BUFLEN);  
		if (len < 0) {									
			perror("ERR: Read from tun_fd");
			free_skb(skb);
			return NULL;
		}
		netdev_receive(skb);
	}
	return NULL;
}

struct netdev* 
netdev_get(uint32_t sip)
{
	if (netdev->addr == sip) {
		return netdev; /* 将static local variable的地址传递出去, netdev包含mac地址信息 */
	}
	else
	{
		return NULL;
	}
}

void 
free_netdev()
{
	free(loop);
	free(netdev);
}

/**\
 * local_ipaddress用于判断addr是否为本机地址.
\**/
int
local_ipaddress(uint32_t addr)
{
	/* 传入的addr是本机字节序表示的ip地址 */
	struct netdev *dev;
	if (!addr) /* INADDR_ANY */
		return 1;
	/* netdev的addr域记录的是本机字节序的ip地址 */
	if (addr == netdev->addr) return 1;
	if (addr == loop->addr) return 1;
	return 0;
}

