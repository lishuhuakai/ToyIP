#ifndef DST_H
#define DST_H

#include "skbuff.h"

struct sk_buff;

int dst_neigh_output(struct sk_buff *skb);

#endif // !DST_H