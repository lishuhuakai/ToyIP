#include "syshead.h"
#include "utils.h"
#include <assert.h>

//
// 这个文件主要用于Debug.
// 
extern int debug;

// run_cmd 用于执行某条命令
int 
run_cmd(char *cmd, ...)
{
	va_list ap;
	char buf[CMDBUFLEN];
	va_start(ap, cmd);
	vsnprintf(buf, CMDBUFLEN, cmd, ap);
	va_end(ap);
	if (debug) { // DEBUG模式下输出信息
		printf("EXEC: %s\n", buf);
	}
	return system(buf);
}

void 
print_err(char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}


uint32_t
parse_ipv4_string(char* addr) {
	uint8_t addr_bytes[4];
	sscanf(addr, "%hhu.%hhu.%hhu.%hhu", &addr_bytes[3], &addr_bytes[2], &addr_bytes[1], &addr_bytes[0]);
	return addr_bytes[0] | addr_bytes[1] << 8 | addr_bytes[2] << 16 | addr_bytes[3] << 24;
}

uint32_t
ip_pton(char *addr)
{
	uint32_t dst = 0;
	if (inet_pton(AF_INET, addr, &dst) != 1) {
		perror("ERR: Parsing inet address failed");
		exit(1);
	}
	/* 需要注意的是inet_pton将字符形式的ip地址转换为网络字节序形式的ip地址 */
	return dst;
}



/* start checksum */


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
		*(uchar *)(&answer) = *(uchar *)ptr;
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

/* end checksum */
