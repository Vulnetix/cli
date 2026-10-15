#include <stdint.h>
#include <stddef.h>

uint32_t checksum_words(void)
{
	uint32_t words[16];
	uint32_t acc = 0;
~>	const uint32_t *end = words + sizeof(words);
	for (const uint32_t *w = words; w < end; w++)
		acc ^= *w;
	return acc;
}

struct record {
	int id;
	int len;
};

void skip_record(struct record *rec, struct record **next)
{
~>	*next = rec + sizeof(struct record);
}
