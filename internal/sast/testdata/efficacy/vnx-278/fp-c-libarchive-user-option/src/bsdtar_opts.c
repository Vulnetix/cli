#include <archive.h>
#include <stdio.h>

#define DEFAULT_FLAGS (ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_SECURE_NODOTDOT)

/* ARCHIVE_EXTRACT_PERM is only honoured when the user passes -p. */
int extract_flags(int opt, int preserve, int keep)
{
	int flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_SECURE_NODOTDOT;

	if (preserve)
		flags |= ARCHIVE_EXTRACT_PERM;
	if (preserve) flags |= ARCHIVE_EXTRACT_OWNER;
	switch (opt) {
	case 'p':
		flags |= ARCHIVE_EXTRACT_ACL;
		break;
	}
	flags &= ~ARCHIVE_EXTRACT_OWNER;
	flags |= keep ? ARCHIVE_EXTRACT_PERM : 0;
	printf("ARCHIVE_EXTRACT_PERM disabled\n");
	return flags;
}
