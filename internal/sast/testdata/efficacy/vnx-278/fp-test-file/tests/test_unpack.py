import tarfile


def test_unpack(tmp_path, sample_tar):
    with tarfile.open(sample_tar) as tar:
        tar.extractall(tmp_path)
