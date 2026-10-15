void copy(char *dst, const char *src)
{
    while (*dst++ = *src++)
        ;
    if (*dst == '\0')
        return;
}
