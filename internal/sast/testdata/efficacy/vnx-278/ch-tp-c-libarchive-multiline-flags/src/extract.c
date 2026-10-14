#include <archive.h>
#include <archive_entry.h>

int extract(const char *filename)
{
	struct archive *a = archive_read_new();
	struct archive *ext = archive_write_disk_new();
	int flags = ARCHIVE_EXTRACT_TIME
~>	    | ARCHIVE_EXTRACT_PERM
~>	    | ARCHIVE_EXTRACT_OWNER;

	archive_read_support_format_all(a);
	archive_write_disk_set_options(ext, flags);
	if (archive_read_open_filename(a, filename, 10240) != ARCHIVE_OK)
		return 1;
	return 0;
}
