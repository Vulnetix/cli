int is_delim(const char *p) {
    if (*p == '"' || *p == '\\') {
        return 1;
    }
    return 0;
}
