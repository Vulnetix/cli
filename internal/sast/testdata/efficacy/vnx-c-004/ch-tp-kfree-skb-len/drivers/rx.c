#include <linux/slab.h>

int rx_done(struct rx *rx, struct pkt *pkt)
{
	kfree(pkt);
~>	rx->bytes += pkt->len;
	return 0;
}
