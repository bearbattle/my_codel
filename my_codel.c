/*
 * My CoDel Implementation
 * By Bear
 * 2021.07.30 - 2021.08.04
 * */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/prefetch.h>
#include <net/pkt_sched.h>
#include <net/my_codel.h>

#define DEFAULT_MY_CODEL_LIMIT 1000

static int my_codel_qdisc_enqueue(packet_t *pkt, struct Qdisc *sch,
				  struct sk_buff **to_free);

static packet_t *my_codel_qdisc_dequeue(struct Qdisc *sch);

static int my_codel_init(struct Qdisc *sch, struct nlattr *opt,
			 struct netlink_ext_ack *extack);

static void my_codel_reset(struct Qdisc *sch);

static int my_codel_change(struct Qdisc *sch, struct nlattr *opt,
			   struct netlink_ext_ack *extack);

static int my_codel_dump(struct Qdisc *sch, struct sk_buff *skb);

static int my_codel_dump_stats(struct Qdisc *sch, struct gnet_dump *d);

static struct Qdisc_ops my_codel_qdisc_ops __read_mostly = {
	.id = "my_codel",
	.priv_size = sizeof(struct my_codel_sched_data),

	.enqueue = my_codel_qdisc_enqueue,
	.dequeue = my_codel_qdisc_dequeue,
	.peek = qdisc_peek_dequeued,
	.init = my_codel_init,
	.reset = my_codel_reset,
	.change = my_codel_change,
	.dump = my_codel_dump,
	.dump_stats = my_codel_dump_stats,
	.owner = THIS_MODULE,
};

static int __init my_codel_module_init(void)
{
	return register_qdisc(&my_codel_qdisc_ops);
}

static void __exit my_codel_module_exit(void)
{
	unregister_qdisc(&my_codel_qdisc_ops);
}

static int my_codel_qdisc_enqueue(packet_t *pkt, struct Qdisc *sch,
				  struct sk_buff **to_free)
{
	struct my_codel_sched_data *q;
	if (likely(qdisc_qlen(sch) < sch->limit)) {
		return my_codel_enqueue(pkt, sch);
	}
	q = qdisc_priv(sch);
	q->drop_overlimit++;
	return qdisc_drop(pkt, sch, to_free);
}

static packet_t *my_codel_qdisc_dequeue(struct Qdisc *sch)
{
	struct my_codel_sched_data *q = qdisc_priv(sch);
	packet_t *pkt = my_codel_deque(sch, &q->state);
	if (q->stats.drop_count && sch->q.qlen) {
		qdisc_tree_reduce_backlog(sch, q->stats.drop_count,
					  q->stats.drop_len);
		q->stats.drop_count = 0;
		q->stats.drop_len = 0;
	}
	if (pkt) {
		qdisc_bstats_update(sch, pkt);
	}
	return pkt;
}

static int my_codel_init(struct Qdisc *sch, struct nlattr *opt,
			 struct netlink_ext_ack *extack)
{
	struct my_codel_sched_data *q = qdisc_priv(sch);
	sch->limit = DEFAULT_MY_CODEL_LIMIT;

	my_codel_state_init(&q->state);
	my_codel_stats_init(&q->stats);
	my_codel_control_init(&q->control);

	/* Should Check MTU */
	if (opt) {
		int err = my_codel_change(sch, opt, extack);
		if (err < 0) {
			return err;
		}
	}
	if (sch->limit >= 1) {
		sch->flags |= TCQ_F_CAN_BYPASS;
	} else {
		sch->flags &= ~TCQ_F_CAN_BYPASS;
	}
	return 0;
}

static void my_codel_reset(struct Qdisc *sch)
{
	struct my_codel_sched_data *q = qdisc_priv(sch);
	qdisc_reset_queue(sch);
	my_codel_state_init(&q->state);
}

static const struct nla_policy my_codel_policy[TCA_CODEL_MAX + 1] = {
	[TCA_MY_CODEL_LIMIT] = { .type = NLA_U32 },
	[TCA_MY_CODEL_ECN] = { .type = NLA_U32 },
	[TCA_MY_CODEL_CE_THRESHOLD] = { .type = NLA_U32 }
};

static int my_codel_change(struct Qdisc *sch, struct nlattr *opt,
			   struct netlink_ext_ack *extack)
{
	struct my_codel_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_MY_CODEL_MAX + 1];
	unsigned int qlen, dropped = 0;
	int err;
	if (!opt) {
		return -EINVAL;
	}

	err = nla_parse_nested(tb, TCA_MY_CODEL_MAX, opt, my_codel_policy,
			       NULL);

	if (err < 0) {
		return err;
	}

	sch_tree_lock(sch);

	if (tb[TCA_MY_CODEL_LIMIT]) {
		sch->limit = nla_get_u32(tb[TCA_CODEL_LIMIT]);
	}

	if (tb[TCA_MY_CODEL_ECN]) {
		q->control.ecn = (nla_get_u32(tb[TCA_CODEL_ECN]) != 0);
	}

	if (tb[TCA_MY_CODEL_CE_THRESHOLD]) {
		u64 val = nla_get_u32(tb[TCA_MY_CODEL_CE_THRESHOLD]);
		q->control.ce_threshold = (val * NSEC_PER_USEC) >> 10;
	}

	qlen = sch->q.qlen;

	while (sch->q.qlen > sch->limit) {
		packet_t *pkt = __qdisc_dequeue_head(&sch->q);
		dropped += qdisc_pkt_len(pkt);
		qdisc_qstats_backlog_dec(
			sch, pkt); /* Update queue stats, Reduce queue Size  */
		rtnl_qdisc_drop(pkt, sch);
	}
	qdisc_tree_reduce_backlog(sch, qlen - sch->q.qlen, dropped);
	sch_tree_unlock(sch);
	return 0;
}

static int my_codel_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct my_codel_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (opts == NULL) {
		nla_nest_cancel(skb, opts);
		return -1;
	}
	if (nla_put_u32(skb, TCA_MY_CODEL_LIMIT, sch->limit) ||
	    nla_put_u32(skb, TCA_CODEL_ECN, q->control.ecn)) {
		nla_nest_cancel(skb, opts);
		return -1;
	}
	if (q->control.ce_threshold != INT_MAX &&
	    nla_put_u32(skb, TCA_CODEL_ECN,
			my_codel_time_to_us(q->control.ce_threshold))) {
		nla_nest_cancel(skb, opts);
		return -1;
	}
	return nla_nest_end(skb, opts);
}

static int my_codel_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	const struct my_codel_sched_data *q = qdisc_priv(sch);
	struct tc_my_codel_xstats st = {
		.maxpacket = q->stats.maxpacket,
		.count = q->state.count,
		.lastcount = q->state.last_count,
		.drop_overlimit = q->drop_overlimit,
		.ldelay = my_codel_time_to_us(q->state.last_delay),
		.dropping = q->state.dropping,
		.ecn_mark = q->stats.ecn_mark,
		.ce_mark = q->stats.ce_mark,
	};
	if (q->state.dropping) {
		my_codel_tdiff_t delta = q->state.drop_next - clock();
		if (delta >= 0) {
			st.drop_next = my_codel_time_to_us(delta);
		} else {
			st.drop_next = -my_codel_time_to_us(-delta);
		}
	}
	return gnet_stats_copy_app(d, &st, sizeof(st));
}

module_init(my_codel_module_init)
module_exit(my_codel_module_exit)

	MODULE_DESCRIPTION("My CoDel Implementation");
MODULE_AUTHOR("Xiong Huchao");
MODULE_LICENSE("Dual BSD/GPL");
