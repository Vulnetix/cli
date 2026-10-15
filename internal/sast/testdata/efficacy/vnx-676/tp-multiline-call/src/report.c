void report(char *buf, const char *title, const char *body)
{
~>    sprintf(buf,
            "%s: %s",
            title, body);
~>    strcpy(
        buf, body);
}
