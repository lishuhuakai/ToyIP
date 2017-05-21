#include "syshead.h"
#include "skbuff.h"
#include "utils.h"
#include "ip.h"
#include "sock.h"
#include "route.h"


int
ip_output(struct sock *sk, struct sk_buff *skb)
{
	struct rtentry *rt;
	struct iphdr *ihdr = ip_hdr(skb);

	rt = route_lookup(ihdr->daddr);	/* 根据目的ip地址查找路由 */

	if (!rt) {
		/* todo */
		return -1;
	}

	skb->dev = rt->dev;				/* dev用于指示 */
	skb->rt = rt;
	skb_push(skb, IP_HDR_LEN);		/* ip头部 */

	ihdr->version = IPV4;			/* ip的版本是IPv4 */
	ihdr->ihl = 0x05;				/* ip头部20字节,也就是说不附带任何选项 */
	ihdr->tos = 0;					/* tos选项不被大多数TCP/IP实现所支持  */
	ihdr->len = skb->len;			/* 整个ip数据报的大小 */
	ihdr->id = ihdr->id;			/* id不变 */
	ihdr->flags = 0;
	ihdr->frag_offset = 0;
	ihdr->ttl = 64;
	ihdr->proto = skb->protocol;
	ihdr->saddr = skb->dev->addr;
	ihdr->daddr = sk->daddr;
	ihdr->csum = 0;

	ip_dbg("out", ihdr);

	ihdr->len = htons(ihdr->len);
	ihdr->id = htons(ihdr->id);
	ihdr->daddr = htonl(ihdr->daddr);
	ihdr->saddr = htonl(ihdr->saddr);
	ihdr->csum = htons(ihdr->csum);
	ihdr->csum = checksum(ihdr, ihdr->ihl * 4, 0);


	return dst_neigh_output(skb);
}