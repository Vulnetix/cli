#include <archive.h>
#include <archive_entry.h>

~>#define EXTRACT_FLAGS (ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL)

int restore(struct archive *ext)
{
	return archive_write_disk_set_options(ext, EXTRACT_FLAGS);
}
