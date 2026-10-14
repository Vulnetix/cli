#include <archive.h>
#include <stdio.h>
#include <unistd.h>

int unpack_flags(int opt_preserve, int c)
{
	int flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_SECURE_NODOTDOT;

	if (opt_preserve)
		flags |= ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_OWNER;
	if (getuid() != 0)
		flags &= ~ARCHIVE_EXTRACT_OWNER;
	switch (c) {
	case 'p':
		flags |= ARCHIVE_EXTRACT_PERM;
		break;
	}
	printf("ARCHIVE_EXTRACT_PERM is off\n");
	return flags;
}
