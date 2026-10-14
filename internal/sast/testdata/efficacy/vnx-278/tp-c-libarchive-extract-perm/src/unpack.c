#include <archive.h>
#include <archive_entry.h>

int unpack(const char *bundle)
{
	struct archive *a = archive_read_new();
	struct archive *ext = archive_write_disk_new();
	struct archive_entry *entry;
~>	int flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL;

	archive_read_support_format_all(a);
	archive_read_open_filename(a, bundle, 10240);
	archive_write_disk_set_options(ext, flags);
	while (archive_read_next_header(a, &entry) == ARCHIVE_OK)
		archive_read_extract2(a, entry, ext);
	return 0;
}

int unpack_as_owner(struct archive *ext)
{
	int flags = ARCHIVE_EXTRACT_TIME
~>	    | ARCHIVE_EXTRACT_OWNER
~>	    | ARCHIVE_EXTRACT_PERM;
	return archive_write_disk_set_options(ext, flags);
}
