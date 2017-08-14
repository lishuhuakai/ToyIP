#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include "syshead.h"
#include "liblevelip.h"
#include <netdb.h>

int
main(int argc, char *argv[])
{
	/* 绑定到一个地址上,然后监听 */
	struct sockaddr_in addr;
	int listenfd, connfd;
	char buff[1024];
	struct in_addr ip;
	int rc = 0;
	bzero(buff, sizeof(buff));
	
	inet_aton("10.0.1.4", &ip);
	listenfd = lvl_socket(AF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(struct sockaddr_in));

	addr.sin_family = AF_INET;
	addr.sin_addr = ip;
	addr.sin_port = htons(41000);

	rc = lvl_bind(listenfd, &addr);

	printf("rc = %d\n", rc);
	rc = lvl_listen(listenfd, 10);

	printf("rc = %d\n", rc);
	
	connfd = lvl_accept(listenfd, NULL);

	int len = strlen("Hi, I am Yihulee! Glad to see you!11111111111111111111\n");
	strncpy(buff, "Hi, I am Yihulee! Glad to see you!11111111111111111111\n", len);
	lvl_write(connfd, buff, len);
	lvl_close(connfd);
	return 0;
}