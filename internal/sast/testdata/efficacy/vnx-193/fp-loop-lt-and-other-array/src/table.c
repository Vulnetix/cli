#define SLOTS 16

static int slots[SLOTS];
static int counts[SLOTS + 1];

void reset(void)
{
	for (int i = 0; i < SLOTS; i++)
		slots[i] = 0;
	for (int i = 0; i <= SLOTS; i++)
		counts[i] = 0;
	for (int n = 1; n <= SLOTS; n++)
		slots[n - 1] = n;
}
