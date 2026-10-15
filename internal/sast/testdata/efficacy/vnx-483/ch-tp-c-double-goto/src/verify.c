int verify(const unsigned char *sig, int len)
{
    int err = 0;
    if ((err = check_header(sig, len)) != 0)
        goto fail;
~>        goto fail;
    if ((err = check_body(sig, len)) != 0)
        goto fail;
fail:
    return err;
}
