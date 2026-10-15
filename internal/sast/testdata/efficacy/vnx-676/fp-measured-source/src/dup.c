char *dup_str(const char *s)
{
    char *p = malloc(strlen(s) + 1);
    if (p == NULL)
        return NULL;
    strcpy(p, s);
    return p;
}

int set_name(char *dst, size_t cap, const char *src)
{
    if (strlen(src) >= cap)
        return -1;
    strcpy(dst, src);
    return 0;
}
