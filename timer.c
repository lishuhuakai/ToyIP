#include "syshead.h"
#include "timer.h"
#include "socket.h"

static LIST_HEAD(timers);
static int tick = 0;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void 
timer_free(struct timer *t)
{
	if (pthread_mutex_trylock(&lock) != 0) { // 如果锁被占用了,也就是暂时还不能释放
		perror("Timer free mutex lock");
		return;
	}
	list_del(&t->list);
	free(t);
	pthread_mutex_unlock(&lock);  // 解锁
}

static struct timer *
timer_alloc()
{
	struct timer *t = calloc(sizeof(struct timer), 1);
	return t;
}

static void 
timers_tick()
{
	struct list_head *item, *tmp = NULL;
	struct timer *t = NULL;

    list_for_each_safe(item, tmp, &timers) {	// 遍历每个timer(定时器),如果到期,则执行,过期或者取消,则释放.
        t = list_entry(item, struct timer, list);

        if (!t->cancelled && t->expires < tick) {
            t->cancelled = 1;
            t->handler(tick, t->arg);
        }

        if (t->cancelled && t->refcnt == 0) {
            timer_free(t);
        }
    }
}

struct timer *
timer_add(uint32_t expire, void (*handler)(uint32_t, void*), void *arg)
{
	struct timer *t = timer_alloc();
	t->refcnt = 1;
	t->expires = tick + expire;
	t->cancelled = 0;
	// 这种现象应该出现得不多吧.
	if (t->expires < tick) {
		print_err("ERR: Timer expiry integer wrap aroud\n");
	}

	t->handler = handler;
	t->arg = arg;
	pthread_mutex_lock(&lock);
	// 因为要对list进行操作,所以要加锁
	// 插入的顺序不要紧
	list_add_tail(&t->list, &timers); // 将t添加到timers的后面
	pthread_mutex_unlock(&lock);
	return t;
}

void
timer_release(struct timer *t)
{
	if (pthread_mutex_lock(&lock) != 0) {
		perror("Timer release lock");
		return;
	}
	if (t) {
		t->refcnt--;
	}
	pthread_mutex_unlock(&lock);
}

void 
timer_cancel(struct timer *t)
{
	// 一旦一个timer被取消,那么在时钟滴答的过程中,这个timer将会被删除
	if (pthread_mutex_lock(&lock) != 0) {
		perror("Timer cancel lock");
		return;
	}
	if (t) {
		t->refcnt--;
		t->cancelled = 1;
	}
	pthread_mutex_unlock(&lock);
}

void *
timers_start()
{
	while (1) {
		if (usleep(1000) != 0) {	// 1s = 1000 000 微秒 这里的话,1秒钟滴答1000次
			perror("Timer usleep");
		}
		tick++;
		timers_tick();
		if (tick % 5000 == 0) {
			socket_debug();
		}
	}
}

int 
timer_get_tick()
{
	return tick;
}
