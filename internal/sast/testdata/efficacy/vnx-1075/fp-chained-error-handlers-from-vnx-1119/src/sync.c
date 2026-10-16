void sync_with_peer(struct peer *p)
{
    char *msg = NULL;
    if (send_cmd(p) < 0)
        goto write_error;
    if (recv_reply(p) < 0)
        goto error;
    return;

error:
    log_failure(p, msg);
    free(msg);
    return;

write_error:
    msg = strdup("send failed");
    goto error;
}
