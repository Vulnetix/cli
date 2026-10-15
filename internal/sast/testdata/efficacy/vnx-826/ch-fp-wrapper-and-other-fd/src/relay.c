#include <unistd.h>

void my_close(int fd);

void relay(int in, int out, int spare)
{
	char buf[512];
	ssize_t n;
	dup2(spare, out);
	close(spare);
	n = read(in, buf, sizeof buf);
	write(out, buf, n);
	my_close(in);
	write(in, buf, 0);
	if (n < 0) {
		close(out);
		return;
	}
	write(out, "\n", 1);
}
