#ifndef UTILS_H
#define UTILS_H

#define CMDBUFLEN 100
#define print_debug(str, ...)	\
	printf(str" - %s:%u\n", ##__VA_ARGS__, __FILE__, __LINE__);

int run_cmd(char *cmd, ...);

void print_err(char *str, ...);
uint32_t parse_ipv4_string(char* addr);
/* 将字符串形式的ip转换为网络字节序形式的ip地址 */
uint32_t ip_pton(char *addr);

/* start wrapper function */

/* end wrapper function */

/* start checksum */
struct pseudo_head {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t zero;
	uint8_t proto;
	uint16_t len;
};

uint32_t sum_every_16bits(void *addr, int count);
uint16_t checksum(void *addr, int count, int start_sum);
int tcp_udp_checksum(uint32_t saddr, uint32_t daddr, uint8_t proto,
	uint8_t *data, uint16_t len);
/* end checksum */
#endif // UTILS_H

