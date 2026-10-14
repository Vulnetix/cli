#include <wordexp.h>

int expand_path(const char *user_path, char *out, size_t n)
{
    wordexp_t we;

~>    if (wordexp(user_path, &we, 0) != 0)
        return -1;
    snprintf(out, n, "%s", we.we_wordv[0]);
    wordfree(&we);
    return 0;
}

int expand_args(const char *line, wordexp_t *we)
{
~>    return wordexp(line, we, WRDE_SHOWERR | WRDE_UNDEF);
}
