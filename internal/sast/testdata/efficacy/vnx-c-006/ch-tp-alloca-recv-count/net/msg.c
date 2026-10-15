#include <alloca.h>
#include <arpa/inet.h>

void on_msg(int fd)
{
	uint16_t n;
	read(fd, &n, sizeof n);
	n = ntohs(n);
	int count = atoi(getenv("ITEMS"));
~>	int items[count];
	(void)items;
}
