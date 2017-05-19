#include "syshead.h"
#include "utils.h"
#include "ip.h"
#include "udp.h"

static int udp_sock_amount = 0;
static LIST_HEAD(sockets);
static pthread_rwlock_t slock = PTHREAD_RWLOCK_INITIALIZER;

void udp_init()
{

}

extern struct net_ops udp_ops;