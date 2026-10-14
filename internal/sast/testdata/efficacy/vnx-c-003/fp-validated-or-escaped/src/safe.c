#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wordexp.h>

int ping_checked(const char *host)
{
    char cmd[256];

    if (!is_valid_hostname(host))
        return -1;
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", host);
    return system(cmd);
}

int ping_allowlisted(const char *host)
{
    char cmd[256];

    if (strspn(host, "abcdefghijklmnopqrstuvwxyz0123456789.-") != strlen(host))
        return -1;
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", host);
    return system(cmd);
}

int open_quoted(const char *path)
{
    gchar *quoted = g_shell_quote(path);
    gchar *cmd = g_strdup_printf("xdg-open %s", quoted);
    int rc = system(cmd);

    g_free(quoted);
    g_free(cmd);
    return rc;
}

int expand_safely(const char *user_path, wordexp_t *we)
{
    return wordexp(user_path, we, WRDE_NOCMD | WRDE_UNDEF);
}

int expand_literal(wordexp_t *we)
{
    return wordexp("~/.config/app", we, 0);
}
