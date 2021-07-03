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

#define DEFAULT_CODEL_LIMIT 1000

static int my_codel_qdisc_enqueue(packet_t *pkt, struct Qdisc *sch,
				  struct sk_buff **to_free);

static packet_t *my_codel_qdisc_dequeue(packet_t *pkt);

static int my_codel_init(struct Qdisc *sch, struct nlattr *opt,
			 struct netlink_ext_ack *extack);

static void my_codel_reset(struct Qdisc *sch);

static int my_codel_change(struct Qdisc *sch, struct nlattr *opt,
			   struct netlink_ext_ack *extack);

static int my_codel_dump(struct Qdisc *sch, struct sk_buff *skb);

static int my_codel_dump_stats(struct Qdisc *sch, struct gnet_dump *d);

static struct Qdisc_ops my_codel_qdisc_ops __read_mostly = {
	.id = "codel",
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

module_init(my_codel_module_init) module_exit(my_codel_module_exit)

MODULE_DESCRIPTION("My CoDel Implementation");
MODULE_AUTHOR("Xiong Huchao");