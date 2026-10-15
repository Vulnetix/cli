int close_all(int fd, int log)
{
    if (fd < 0) // nothing to close
        return 0;
~>        log_close(log);
    return close(fd);
}
