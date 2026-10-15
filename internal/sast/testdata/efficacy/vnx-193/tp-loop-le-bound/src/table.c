#define SLOTS 16

static int slots[SLOTS];

void reset(void)
{
	int i;
~>	for (i = 0; i <= SLOTS; i++)
		slots[i] = 0;
}

void fill(unsigned char *out)
{
	unsigned char pad[8];
~>	for (size_t k = 0; k <= sizeof(pad); k++) {
		pad[k] = 0x5c;
	}
	out[0] = pad[0];
}
