// Never call gets(buf) or strcpy(a, b).
/*
 * sprintf(buf, "%s", s) overflows
 */
void f(Buf &b, Reader *r)
{
    b.strcpy(src);
    r->gets(line);
    puts("avoid strcat(dst, src) here");
    my_sprintf(buf, "%s", s);
}
