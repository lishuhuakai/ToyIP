#include "syshead.h"
#include "route.h"
#include "dst.h"
#include "netdev.h"
#include "list.h"
#include "ip.h"

static LIST_HEAD(routes);

extern struct netdev *netdev;
extern struct netdev *gatedev;
extern struct netdev *loop;

extern char *tapaddr;
extern char *taproute;

static struct rtentry* 
route_alloc(uint32_t dst, uint32_t gateway, uint32_t netmask,
	uint8_t flags, uint32_t metric, struct netdev *dev)
{
	struct rtentry *rt = malloc(sizeof(struct rtentry));
	list_init(&rt->list);
	rt->dst = dst;		// 目的地址
	rt->gateway = gateway;
	rt->netmask = netmask;
	rt->flags = flags;
	rt->metric = metric;
	rt->dev = dev;
	return rt;
}

// route_add 添加路由项
void 
route_add(uint32_t dst, uint32_t gateway, uint32_t netmask, uint8_t flags,
	uint32_t metric, struct netdev *dev)
{
	// dst 目的网段
	// gateway 网关
	// netmask 子网掩码
	struct rtentry *rt = route_alloc(dst, gateway, netmask, flags, metric, dev);
	list_add_tail(&rt->list, &routes);  // 添加到尾部
}

void 
route_init()
{
	route_add(loop->addr, 0, 0xff000000, RT_LOOPBACK, 0, loop);  // 127.0.0.1
	route_add(netdev->addr, 0, 0xffffff00, RT_HOST, 0, netdev);	 // 10.0.1.4
	route_add(0, ip_parse(tapaddr), 0, RT_GATEWAY, 0, netdev); // 默认的网关
}

// route_lookup 从路由表中查找路由
struct rtentry  *
	route_lookup(uint32_t daddr)
{
	struct list_head *item;
	struct rtentry *rt = NULL;

	list_for_each(item, &routes) {
		rt = list_entry(item, struct rtentry, list);
		if ((rt->netmask & daddr) == rt->dst) break;
		// 如果不能匹配的话,我们默认使用最后一个项,也就是网关
	}
	return rt;
}

void 
free_routes()
{
	struct list_head *item, *tmp;
	struct rtentry *rt;

	list_for_each_safe(item, tmp, &routes) {
		rt = list_entry(item, struct rtentry, list);
		list_del(item);
		free(rt);
	}
}