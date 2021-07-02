/**
 * My CoDel Implementation
 * By Bear
 * 2021.07.30 - 2021.08.04
 * @see: https://queue.acm.org/appendices/codel.html
 * */

#ifndef LINUX_5_8_MY_CODEL_H
#define LINUX_5_8_MY_CODEL_H

#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>

typedef u32 my_codel_time_t;
typedef s32 my_codel_tdiff_t;
typedef bool my_flag_t;
typedef struct sk_buff packet_t;

/* Get current kernel time in ms */
static inline my_codel_time_t clock(void)
{
	return ktime_get_ns() >> 10; /* ns / 1000 = ms */
}

#define MS2TIME(a) (((a)*NSEC_PER_MSEC) >> 10) /* ns / 1000 = ms */

#define my_codel_time_after(a, b)                                              \
	(typecheck(my_codel_time_t, a) && typecheck(my_codel_time_t, b) &&     \
	 ((my_codel_tdiff_t)((a) - (b)) > 0))
#define my_codel_time_before(a, b) my_codel_time_after(b, a)
#define my_codel_time_after_eq(a, b)                                           \
	(typecheck(my_codel_time_t, a) && typecheck(my_codel_time_t, b) &&     \
	 ((my_codel_tdiff_t)((a) - (b)) >= 0))
#define my_codel_time_before_eq(a, b) my_codel_time_after_eq(b, a)

static inline u32 my_codel_time_to_us(my_codel_time_t val)
{
	u64 val_ns = ((u64)val << 10);
	do_div(val_ns, NSEC_PER_USEC);
	return (u32)val_ns;
}

/**
 * My CoDel Control Block (cb)
 * @enqueue_time: time when this packet join the queue
 */
struct my_codel_cb {
	my_codel_time_t enqueue_time;
};

static struct my_codel_cb *get_my_codel_cb(const packet_t *pkt)
{
	/* Check Control Block during compiling */
	qdisc_cb_private_validate(pkt, sizeof(struct my_codel_cb));
	return (struct my_codel_cb *)pkt->data;
}

static my_codel_time_t my_codel_get_enqueue_time(const packet_t *pkt)
{
	return get_my_codel_cb(pkt)->enqueue_time;
}

static void my_codel_set_enqueue_time(packet_t *pkt)
{
	get_my_codel_cb(pkt)->enqueue_time = clock();
}

/**
 * PER-QUEUE STATE (CODEL_QUEUE_T INSTANCE VARIABLES)
 * @var {my_codel_time_t} first_above_time
 * 	Time when we'll declare we're above target (0 if below)
 * @var {my_codel_time_t} drop_next
 * 	Time to drop next packet
 * @var {uint32_t} count
 * 	Packets dropped since going into drop state
 * @var {flag_t} dropping
 * 	Equal to 1(true) if in drop state
 */
struct my_codel_state {
	my_codel_time_t first_above_time;
	my_codel_time_t drop_next;
	uint32_t count;
	my_flag_t dropping;
};

/* CONSTANTS */
/* Target queue delay (5 ms) */
const my_codel_time_t target = MS2TIME(5);
/* Sliding minimum time window width (100 ms) */
const my_codel_time_t interval = MS2TIME(100);
/* Maximum packet size in bytes (should use interface MTU) */
const u_int maxpacket = 512;

/**
 * Base Queue Class for queue objects
 * @method enqueue()
 * 	Add a packet to queue.
 * @method dequeue()
 * 	Get a packet from queue.
 * @method bytes() Returns the current queue size in bytes.
 * 	This can be an approximate value.
 */

#endif /* LINUX_5_8_MY_CODEL_H */
