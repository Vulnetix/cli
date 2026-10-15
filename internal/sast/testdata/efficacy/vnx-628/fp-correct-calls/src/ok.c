#include <stdio.h>
#include <string.h>

void ok(char *buf, size_t n, const char *name, int count)
{
	memset(buf, 0, n);
	memset(buf, '\0', sizeof(buf));
	memset(buf, 0, 0);
	printf("hello world\n");
	printf("%s has %d items\n", name, count);
	printf("%s=%d\n", get_name(name, 1), max(count, 2));
	fprintf(stderr, "%-10s|%5.2f\n", name, compute(count, 3, 4));
	snprintf(buf, n, "%s/%s", dir_of(name), base_of(name));
}
