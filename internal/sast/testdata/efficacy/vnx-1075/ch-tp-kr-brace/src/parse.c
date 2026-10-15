int skip_blanks(const char *s, int i) {
    top:
        if (s[i] == ' ' || s[i] == '\t') {
            i++;
~>            goto top ;
        }
    return i;
}
