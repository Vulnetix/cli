#include <inttypes.h>
#include <stdio.h>

void fmt(uint64_t v, int width, const char *s)
{
	printf("value %" PRIu64 "\n", v);
	printf("%*d|%.*s\n", width, 3, width, s);
	printf("%2$s %1$s\n", s, s);
	printf("%s %d\n",
	       s, width);
	printf("%s %d\n", s, width), puts("done");
	printf("%m\n");
	my_printf("%s %s", s);
}
