#include <future>
#include <unistd.h>

int read_shadow();

int run_backup()
{
	auto job = std::async(std::launch::async, [] { return 0; });
~>	if (seteuid(0) != 0)
		return -1;
	int rc = read_shadow();
	seteuid(getuid());
	return rc + job.get();
}
