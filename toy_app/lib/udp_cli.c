#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include "liblevelip.h"

#define SERV_PORT 40000
#define MAXLINE 1024


void
dg_cli(FILE *fp, int sockfd, const struct sockaddr_in *pservaddr, socklen_t servlen)
{
	int n;
	char sendline[MAXLINE], recvline[MAXLINE + 1];
	int len = strlen(recvline);
	while (fgets(sendline, MAXLINE, fp) != NULL) {
		lvl_sendto(sockfd, sendline, strlen(sendline), pservaddr);
		n = lvl_recvfrom(sockfd, recvline, MAXLINE, NULL);
		if (n > 0) {
			recvline[n] = 0;
			fputs(recvline, stdout);
		}
	}
}

int
main(int argc, char *argv[])
{
	int sockfd;
	struct sockaddr_in servaddr;

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	inet_pton(AF_INET, "10.0.1.5", &servaddr.sin_addr);
	servaddr.sin_port = htons(SERV_PORT);

	sockfd = lvl_socket(AF_INET, SOCK_DGRAM, 0);
	dg_cli(stdin, sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
}