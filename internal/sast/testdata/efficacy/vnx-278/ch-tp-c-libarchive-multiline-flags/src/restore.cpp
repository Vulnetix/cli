#include <archive.h>

#include "restore.h"

void Restore::configure(archive *writer)
{
~>    archive_write_disk_set_options(writer, ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS | ARCHIVE_EXTRACT_PERM);
}
