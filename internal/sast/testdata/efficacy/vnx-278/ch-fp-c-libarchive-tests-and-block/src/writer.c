#include <archive.h>
#include <sys/stat.h>

struct opts {
	int flags;
	int same_permissions;
	int is_root;
};

#define ARCHIVE_EXTRACT_PERM_COMPAT (0x0002)

static int keep_modes(const struct opts *o)
{
	int keep = (o->flags & ARCHIVE_EXTRACT_PERM) != 0;
	return keep;
}

static mode_t effective_mode(const struct opts *o, mode_t mode, mode_t mask)
{
	return (o->flags & ARCHIVE_EXTRACT_PERM) ? mode : mode & ~mask;
}

int configure(struct opts *o)
{
	int flags = ARCHIVE_EXTRACT_TIME;

	if (o->same_permissions) {
		flags |= ARCHIVE_EXTRACT_PERM;
		flags |= ARCHIVE_EXTRACT_ACL;
	}
	if (o->is_root)
	{
		flags |= ARCHIVE_EXTRACT_OWNER;
	}
	else
		flags &= ~ARCHIVE_EXTRACT_OWNER;
	return flags;
}
