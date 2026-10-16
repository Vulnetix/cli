def test_x(mode, uid, gid, owner, group):
    assert (mode & 0o400 and uid == owner) or (mode & 0o040 and gid == group and not uid == 0) or (mode & 0o004 and ~mode & 0o002 == 0 and mode >> 9 | 1 != 0)
