size_t length(const char *s)
{
    const char *p = s;
    size_t n;
    while (*p++);
    for (n = 0; s[n]; n++);
    do {
        n--;
    } while (n > 10);
    switch (n) {
    case 1:
        n = 2;
        n = 3;
        break;
    }
    return n;
}
