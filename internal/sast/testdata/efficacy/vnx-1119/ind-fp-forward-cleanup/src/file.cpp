int load(const char *p)
{
    char *buf = new char[64];
    if (!buf)
        goto cleanup;
    if (read_into(p, buf) < 0)
        goto cleanup;
    use(buf);
cleanup:
    delete[] buf;
    return 0;
}
