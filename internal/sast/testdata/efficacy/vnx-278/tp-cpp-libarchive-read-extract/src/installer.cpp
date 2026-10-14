#include <archive.h>
#include <archive_entry.h>

namespace installer {

int extract_entry(struct archive *a, struct archive_entry *entry)
{
~>	return archive_read_extract(a, entry, ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_OWNER);
}

} // namespace installer
