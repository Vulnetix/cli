void migrate(struct client *c)
{
    int retries = 0;
    int fd;

try_again:
    fd = connect_target(c);
    if (fd < 0)
        goto socket_err;
    if (send_payload(fd, c) < 0)
        goto socket_err;
    reply_ok(c);
    return;

socket_err:
    close(fd);
    if (retries++ < 3)
~>        goto try_again;
    reply_error(c);
}
