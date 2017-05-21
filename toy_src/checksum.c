#include "syshead.h"
#include "checksum.h"


uint32_t 
sum_every_16bits(void *addr, int count)
{
	register uint32_t sum = 0;
	uint16_t *ptr = addr;
	uint16_t answer = 0;

	while (count > 1) {
		/*  This is the inner loop */
		sum += *ptr++;
		count -= 2;
	}

	if (count == 1) {
		/*
		 这里有一个细节需要注意一下. unsigned char 8bit
		 answer 16bit			将answer强制转换为8bit,会使得最后剩下的8bit被放入到x中
		 +-----+-----+			+-----+-----+
		 |  8  |  8  |			|xxxxx|     |
		 +-----+-----+			+-----+-----+
		 */
		*(unsigned char *)(&answer) = *(unsigned char *)ptr;
		sum += answer;
	}

	return sum;
}

/* checksum 用于计算校验值 */
uint16_t 
checksum(void *addr, int count, int start_sum)
{
	uint32_t sum = start_sum;
	sum += sum_every_16bits(addr, count);

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return ~sum;
}

int 
tcp_udp_checksum(uint32_t saddr, uint32_t daddr, uint8_t proto,
	uint8_t *data, uint16_t len)
{
	/* we need to ensure that saddr and daadr are in netowrk byte order */
	uint32_t sum = 0;
	struct pseudo_head head;
	memset(&head, 0, sizeof(struct pseudo_head));
	/* 需要保证传入的daddr以及saddr是网络字节序 */
	head.daddr = daddr;
	head.saddr = saddr;
	/* 对于TCP来说,proto = 0x06,而对于UDP来说proto = 0x17 */
	head.proto = proto; /* sizeof(proto) == 1,  
						对于只有1个字节的数据,不需要转换字节序 */
	head.len = htons(len);
	sum = sum_every_16bits(&head, sizeof(struct pseudo_head));
	return checksum(data, len, sum);
}