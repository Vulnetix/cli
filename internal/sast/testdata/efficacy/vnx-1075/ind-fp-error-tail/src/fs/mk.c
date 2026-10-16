int mk(const char *p)
{
    int fd;
    fd = open(p, 0);
    if (fd < 0)
        goto fail;
    return fd;
fail:
    log_err("open failed");
    return -1;
}
