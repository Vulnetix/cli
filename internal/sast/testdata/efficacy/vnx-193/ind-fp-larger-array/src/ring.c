#define SLOTS 16

/* One extra slot holds the sentinel written by ring_seal(). */
static int ring[SLOTS + 1];

void ring_clear(void)
{
	int i;
	for (i = 0; i <= SLOTS; i++)
		ring[i] = 0;
}
