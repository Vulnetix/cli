#include <fcntl.h>
#include <stdio.h>
#include <assert.h>

static void test_open_job(void)
{
	char path[256];

	snprintf(path, sizeof(path), "%s/%s.job", "/tmp/spool", "fixture");
	assert(open(path, O_RDONLY) >= 0);
}
