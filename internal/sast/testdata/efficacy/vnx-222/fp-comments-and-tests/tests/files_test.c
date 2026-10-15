#include <fcntl.h>
#include <stdio.h>

void test_open(void)
{
	char path[32];
	snprintf(path, sizeof(path), "/tmp/%s", "fixture");
	open(path, O_RDONLY);
}
