static int verify(ctx_t *ctx, buf_t *sig)
{
    int err;

    if ((err = hash_update(ctx, sig->client)) != 0)
        goto fail;
    if ((err = hash_update(ctx, sig->server)) != 0)
        goto fail;
~>        goto fail;
    if ((err = hash_final(ctx, sig->out)) != 0)
        goto fail;

    err = check_signature(ctx, sig);
fail:
    return err;
}
