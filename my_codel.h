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
	uint32_t last_delay;
	my_flag_t dropping;
};

/**
 * struct codel_stats - contains codel shared variables and stats
 * @maxpacket:	largest packet we've seen so far
 * @drop_count:	temp count of dropped packets in dequeue()
 * @drop_len:	bytes of dropped packets in dequeue()
 * @ecn_mark:	number of packets we ECN marked instead of dropping
 * @ce_mark:	number of packets CE marked because sojourn time was above ce_threshold
 */
struct my_codel_stats {
	u32 maxpacket;
	u32 drop_count;
	u32 drop_len;
	u32 ecn_mark;
	u32 ce_mark;
};

struct my_codel_control {
	my_codel_time_t ce_threshold;
	bool ecn;
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
typedef void (*drop_func_t)(packet_t *pkt, void *ctx);

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
	drop_func_t drop;
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

/**
 * my_drop
 * Get current queue size in byte
 * @param {packet_t *} pkt
 * 	Current Queue as strcut Queue Discipline
 * @param {void *} ctx
 * 	Context of current queue
 * 	Will be converted to Qdisc
 */
static void my_drop(packet_t *pkt, void *ctx)
{
	struct Qdisc *sch = ctx;
	kfree_skb(pkt);
	qdisc_qstats_drop(sch);
}
static const my_queue_t base_queue = { .enqueue = my_enqueue,
				       .dequeue = my_dequeue,
				       .bytes = my_bytes,
				       .drop = my_drop };

struct my_codel_sched_data {
	struct my_codel_state state;
	struct my_codel_stats stats;
	struct my_codel_control control;
	u32 drop_overlimit;
};

static void my_codel_state_init(struct my_codel_state *state)
{
	state->first_above_time = 0;
	state->drop_next = 0;
	state->last_count = state->count = 0;
	state->last_delay = 0;
	state->dropping = false;
}

static void my_codel_stats_init(struct my_codel_stats *stats)
{
	stats->maxpacket = 0;
}

static void my_codel_control_init(struct my_codel_control *control)
{
	control->ce_threshold = INT_MAX;
	control->ecn = false;
}

static int my_codel_enqueue(packet_t *pkt, struct Qdisc *sch)
{
	my_codel_set_enqueue_time(pkt);
	return base_queue.enqueue(pkt, sch);
}

/**
 * Since the degree of multiplexing and nature of the traffic sources is unknown,
 * CoDel acts as a closed-loop servo system that gradually increases the frequency
 * of dropping until the queue is controlled (sojourn time goes below target).
 * This is the control law that governs the servo. It has this form because of
 * the sqrt(p) dependence of TCP throughput on drop probability.1 Note that for
 * embedded systems or kernel implementation the inverse sqrt can be computed
 * efficiently using only integer multiplication.
 */
static my_codel_time_t my_codel_control_law(my_codel_time_t t, uint32_t count)
{
	my_codel_time_t val = interval;
	u32 sqrt = int_sqrt(count);
	do_div(val, sqrt);
	return t + (my_codel_time_t)val;
}

/**
 * This is a helper routine the does the actual packet dequeue and tracks whether
 * the sojourn time is above or below target and, if above, if it has remained above
 * continuously for at least interval. It returns two values, a Boolean indicating
 * whether it is OK to drop (sojourn time above target for at least interval) and
 * the packet dequeued.
 * @p packet_t* Pointer to dequeued packet
 * @ok_to_drop flag_t whether it is OK to drop
 */
typedef struct {
	packet_t *p;
	my_flag_t ok_to_drop;
} my_dodeque_result;

static my_dodeque_result my_codel_dodeque(my_codel_time_t now,
					  struct Qdisc *sch,
					  struct my_codel_state *state)
{
	my_dodeque_result r = { .p = base_queue.dequeue(sch),
				.ok_to_drop = false };
	if (r.p == NULL) {
		state->first_above_time = 0;
	} else {
		my_codel_time_t sojourn_time =
			now - my_codel_get_enqueue_time(r.p);
		state->last_delay = sojourn_time;
		if (my_codel_time_before(sojourn_time, target) ||
		    base_queue.bytes(sch) < maxpacket) {
			/* went below so we'll stay below for at least interval */
			state->first_above_time = 0;
		} else {
			if (state->first_above_time == 0) {
				/* just went above from below. if we stay above */
				/* for at least interval we'll say it's ok to drop */
				state->first_above_time = now + interval;
			} else if (my_codel_time_after(
					   now, state->first_above_time)) {
				r.ok_to_drop = 1;
			}
		}
	}
	return r;
}

/**
 * All of the work of CoDel is done here. There are two branches:
 * 		if we're in packet-dropping state (meaning that the
 * 			queue-sojourn time has gone above target and
 * 		 	hasn't come down yet),
 * 		 	then we need to check if it's time to leave or
 * 				if it's time for the next drop(s);
 *  	if we're not in dropping state,
 * 			then we need to decide if it's time to enter and
 * 				do the initial drop.
 */

packet_t *my_codel_deque(struct Qdisc *sch, struct my_codel_state *state)
{
	my_codel_time_t now = clock();
	my_dodeque_result r = my_codel_dodeque(now, sch, state);
	if (r.p == NULL) {
		/* an empty queue takes us out of dropping state */
		state->dropping = 0;
		return r.p;
	}
	if (state->dropping) {
		if (!r.ok_to_drop) {
			/* sojourn time below target - leave dropping state */
			state->dropping = 0;
		} else if (my_codel_time_after_eq(now, state->drop_next)) {
			/*
			* It's time for the next drop. Drop the current packet and dequeue the next.
			* The dequeue might take us out of dropping state.
			* If not, schedule the next drop.
			* A large backlog might result in drop rates so high that the next drop should happen now;
			* hence, the while loop.
			*/
			while (my_codel_time_after_eq(now, state->drop_next) &&
			       state->dropping) {
				base_queue.drop(r.p, sch);
				++state->count;
				r = my_codel_dodeque(now, sch, state);
				if (!r.ok_to_drop)
					/* leave dropping state */
					state->dropping = 0;
				else
					/* schedule the next drop. */
					state->drop_next = my_codel_control_law(
						state->drop_next, state->count);
			}
		}
		/*
		* If we get here, then we're not in dropping state.
		* If the sojourn time has been above target for interval,
		* 	then we decide whether it's time to enter dropping state.
		* We do so if we've been either in dropping state recently or above target fora relatively long time.
		* The "recently" check helps ensure that when we're successfully controlling the queue
		* we react quickly (in one interval) and start with the drop rate that controlled the queue last time
		* rather than relearn the correct rate from scratch.
		* If we haven't been dropping recently,
		* 	the "long time above" check adds some hysteresis to the state entry so
		*  we don't drop on a slightly bigger-than-normal traffic pulse into an otherwise quiet queue.
		*/
	} else if (r.ok_to_drop &&
		   ((now - state->drop_next < interval) ||
		    (now - state->first_above_time >= interval))) {
		base_queue.drop(r.p, sch);
		r = my_codel_dodeque(now, sch, state);
		state->dropping = 1;
		/* If we're in a drop cycle, the drop rate that controlled the queue */
		/* on the last cycle is a good starting point to control it now. */
		if (now - state->drop_next < interval)
			state->count = state->count > 2 ? state->count - 2 : 1;
		else
			state->count = 1;
		state->drop_next = my_codel_control_law(now, state->count);
	}
	return (r.p);
}

/* MY_CODEL */

enum {
	TCA_MY_CODEL_UNSPEC,
	TCA_MY_CODEL_LIMIT,
	TCA_MY_CODEL_ECN,
	TCA_MY_CODEL_CE_THRESHOLD,
	__TCA_MY_CODEL_MAX
};

#define TCA_MY_CODEL_MAX	(__TCA_MY_CODEL_MAX - 1)

struct tc_my_codel_xstats {
	__u32	maxpacket; /* largest packet we've seen so far */
	__u32	count;	   /* how many drops we've done since the last time we
			    * entered dropping state
			    */
	__u32	lastcount; /* count at entry to dropping state */
	__u32	ldelay;    /* in-queue delay seen by most recently dequeued packet */
	__s32	drop_next; /* time to drop next packet */
	__u32	drop_overlimit; /* number of time max qdisc packet limit was hit */
	__u32	ecn_mark;  /* number of packets we ECN marked instead of dropped */
	__u32	dropping;  /* are we in dropping state ? */
	__u32	ce_mark;   /* number of CE marked packets because of ce_threshold */
};

#endif /* LINUX_5_8_MY_CODEL_H */