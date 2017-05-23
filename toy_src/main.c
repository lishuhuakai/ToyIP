#include "syshead.h"
#include "netdev.h"
#include "tuntap.h"
#include "route.h"
#include "ipc.h"
#include "timer.h"
#include "tcp.h"
#include "TEST.h"

int debug = 1;
int running = 1;
void * start_ipc_listener();
#define THREAD_CORE 0
#define THREAD_TIMERS 1
#define THREAD_IPC 2
#define THREAD_SIGNAL 3

static pthread_t threads[4];
sigset_t mask;

static void *
stop_stack_handler(void *arg)
{
	int err, signo;

	for (;;) {
		err = sigwait(&mask, &signo);
		if (err != 0) {
			print_err("Sigwait failed: %d\n", err);
		}

		switch (signo) {
		case SIGINT:
		case SIGQUIT:
			running = 0;
			pthread_cancel(threads[THREAD_IPC]);
			//pthread_cancel(threads[THREAD_CORE]);
			pthread_cancel(threads[THREAD_TIMERS]);
			return 0;
		default:
			printf("Unexpected signal %d\n", signo);
		}
	}
}

static void 
init_signals()
{
	int err;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);

	if ((err = pthread_sigmask(SIG_BLOCK, &mask, NULL)) != 0) {
		print_err("SIG_BLOCK error\n");
		exit(1);
	}
}

static void
create_thread(pthread_t id, void *(*func)(void *))
{
	if (pthread_create(&threads[id], NULL, func, NULL) != 0) {
		print_err("Could not create core thread\n");
	}
}

static void
run_threads()
{
	create_thread(THREAD_IPC, start_ipc_listener);
	create_thread(THREAD_TIMERS, timers_start);
	//create_thread(THREAD_SIGNAL, stop_stack_handler);
}

static void 
init_stack()
{
	tun_init();      /* ≥ı ºªØ–Èƒ‚Õ¯ø® */
	netdev_init();
	route_init();
	tcp_init();
}


int 
main(int argc, char *argv[])
{
	init_stack();
	run_threads();
	netdev_rx_loop();
	getchar();
	return 0;
}