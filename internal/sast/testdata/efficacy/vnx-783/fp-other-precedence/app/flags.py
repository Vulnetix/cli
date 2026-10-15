def writable(mode, S_IWOTH):
    return mode & S_IWOTH == 0
