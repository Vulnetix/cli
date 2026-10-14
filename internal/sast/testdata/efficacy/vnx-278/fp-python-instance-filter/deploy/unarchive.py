import tarfile


def unarchive(archive_filename, dest_dir):
    archive = tarfile.open(archive_filename, "r:gz")

    def checked_filter(member, path):
        return tarfile.tar_filter(member, path)

    archive.extraction_filter = checked_filter
    archive.extractall(dest_dir)
    archive.close()
