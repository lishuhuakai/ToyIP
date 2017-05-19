#include "tuntap.h"
#include "syshead.h"
#include "basic.h"
#include "utils.h"

static int tun_fd;
static char* dev;

char *tapaddr = "10.0.1.5";		// tap设备的地址
char *taproute = "10.0.1.0/24";
char *stackaddr = "10.0.1.4";

static int 
set_if_route(char *dev, char *cidr)
{
	// ip route add dev tap0 10.0.1.0/24 
	return run_cmd("ip route add dev %s %s", dev, cidr);
}

static int 
set_if_address(char *dev, char *cidr)
{
	// ip address add dev tap0 10.0.1.5 # 给tap0设置ip地址
	return run_cmd("ip address add dev %s local 10.0.1.5/24", dev, cidr);
}

static int 
set_if_up(char* dev)
{
	// ip link set dev tap0 up  # 启动设备
	return run_cmd("ip link set dev %s up", dev);
}

static int 
tun_alloc(char *dev)
{
	struct ifreq ifr;
	int fd, err;
	if ((fd = open("/dev/net/tap", O_RDWR)) < 0) {
		perror("Cannot open TUN/TAP dev\n"
			"Make sure one exists with "
			"'$ mknod /dev/net/tap c 10 200'");
		exit(1);
	}
	CLEAR(ifr);  // 清空

	/* Flags: IFF_TUN	- TUN device (no Ethernet headers)
	 *		  IFF_TAP	- TAP device
	 *		  
	 *		  IFF_NO_PI - Do not provide packet information
	 */
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if (*dev) {
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {  // 打开虚拟网卡
		perror("ERR: Could not ioctl tun");
		close(fd);
		return err;
	}

	strcpy(dev, ifr.ifr_name);
	return fd;
}

int 
tun_read(char *buf, int len)
{
	return read(tun_fd, buf, len);
}

int 
tun_write(char *buf, int len)
{
	return write(tun_fd, buf, len);
}

void 
tun_init()
{
	dev = calloc(10, 1); // 分配10个长度为1个字节的空间给dev
	tun_fd = tun_alloc(dev);
	if (set_if_up(dev) != 0) {
		print_err("ERROR when setting up if\n");
	}

	if (set_if_route(dev, taproute) != 0) {
		print_err("ERROR when setting route for if\n");
	}

	if (set_if_address(dev, tapaddr) != 0) {
		print_err("ERROR when setting addr for if \n");
	}
}

void 
free_tun()
{
	free(dev);
}