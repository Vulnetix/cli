~>#pragma strict_gs_check(off)

~>__declspec(safebuffers) void handler(const char *p) {
    char tmp[32];
    (void)p; (void)tmp;
}
