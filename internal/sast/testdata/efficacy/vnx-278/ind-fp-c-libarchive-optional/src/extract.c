#include <archive.h>

int setup(struct archive *ext, int preserve)
{
	int flags = ARCHIVE_EXTRACT_TIME;
	if (preserve)
		flags |= ARCHIVE_EXTRACT_PERM;
	archive_write_disk_set_options(ext, flags);
	if ((flags & ARCHIVE_EXTRACT_PERM) != 0)
		return 1;
	return 0;
}
