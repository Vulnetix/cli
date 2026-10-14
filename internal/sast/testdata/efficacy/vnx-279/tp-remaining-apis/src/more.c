#include <fcntl.h>
#include <sys/stat.h>

void more(const char *link)
{
~>	fchmodat(AT_FDCWD, "/usr/local/bin/tool", 04755, 0);
~>	lchmod(link, S_ISUID | 0755);
}
