int load(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (read_header(fp) != 0) {
        fclose(fp);
        return -1;
    }
    parse(fp);
    fclose(fp);
    return 0;
}

int load2(int fd)
{
    if (bad(fd)) {
        close(fd);
        goto out;
    }
    close(fd);
out:
    return 0;
}
