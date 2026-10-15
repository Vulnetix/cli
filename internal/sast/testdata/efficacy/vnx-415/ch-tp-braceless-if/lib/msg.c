#include <stdlib.h>

int send_message(struct conn *c, char *msg)
{
	int err = conn_write(c, msg);
	if (err)
		free(msg);
	stats_bump(c);
~>	free(msg);
	return err;
}
