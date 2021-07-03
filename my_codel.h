/**
 * My CoDel Implementation
 * By Bear
 * 2021.06.30 - 2021.07.04
 * @see: https://queue.acm.org/appendices/codel.html
 */

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
	uint32_t last_count;
	my_codel_time_t ldelay;
	my_flag_t dropping;
};

/**
 * struct codel_stats - contains codel shared variables and stats
 * @maxpacket:	largest packet we've seen so far
 * @drop_count:	temp count of dropped packets in dequeue()
 * @drop_len:	bytes of dropped packets in dequeue()
 * ecn_mark:	number of packets we ECN marked instead of dropping
 * ce_mark:	number of packets CE marked because sojourn time was above ce_threshold
 */
struct my_codel_stats {
	u32 maxpacket;
	u32 drop_count;
	u32 drop_len;
	u32 ecn_mark;
	u32 ce_mark;
};

/* CONSTANTS */
/* Target queue delay (5 ms) */
const my_codel_time_t target = MS2TIME(5);
/* Sliding minimum time window width (100 ms) */
const my_codel_time_t interval = MS2TIME(100);
/* Maximum packet size in bytes (should use interface MTU) */
const u_int maxpacket = 512;

/* Some function pointer type for add into my_queue_t */
typedef int (*enqueue_func_t)(packet_t *pkt, struct Qdisc *sch);
typedef packet_t *(*dequeue_func_t)(void *ctx);
typedef u32 (*bytes_func_t)(struct Qdisc *sch);

/**
 * my_queue_t
 * Base Queue Class for queue objects
 * @method enqueue()
 * 	Add a packet to queue.
 * @method dequeue()
 * 	Get a packet from queue.
 * @method bytes() Returns the current queue size in bytes.
 * 	This can be an approximate value.
 */
typedef struct {
	enqueue_func_t enqueue;
	dequeue_func_t dequeue;
	bytes_func_t bytes;
} my_queue_t;

/**
 * my_enqueue
 * Add a packet to current queue
 * @param {packet_t *} pkt
 * 	The packet to be added to the queue.
 * @param {struct Qdisc *} sch
 * 	Current Queue as strcut Queue Discipline
 * @return {int} 0 if no error
 */
static int my_enqueue(packet_t *pkt, struct Qdisc *sch)
{
	return qdisc_enqueue_tail(pkt, sch);
}

/**
 * my_dequeue
 * Pop a packet from current queue
 * @param {void *} ctx
 * 	Context of current queue
 * 	Will be converted to Qdisc
 * @return {packet_t *}
 * 	Popped packet. NULL if error or empty queue.
 */
static packet_t *my_dequeue(void *ctx)
{
	struct Qdisc *sch = ctx;
	packet_t *pkt = __qdisc_dequeue_head(&sch->q);

	if (pkt)
		sch->qstats.backlog -= qdisc_pkt_len(pkt);

	/* prefetch(&skb->end); */
	return pkt;
}

/**
 * my_bytes
 * Get current queue size in byte
 * @param {struct Qdisc *} sch
 * 	Current Queue as strcut Queue Discipline
 * @return {u32}
 * 	Current Queue size in byte
 */
static u32 my_bytes(struct Qdisc *sch)
{
	return sch->qstats.backlog;
}

static const my_queue_t base_queue = { .enqueue = my_enqueue,
				       .dequeue = my_dequeue,
				       .bytes = my_bytes };

struct my_codel_sched_data {
	struct my_codel_state state;
	struct my_codel_stats stats;
	u32 drop_overlimit;
};

#endif /* LINUX_5_8_MY_CODEL_H */