#ifndef COMPAT_H
#define COMPAT_H

char *mktemp(char *tmpl);
extern char *tmpnam(char *s);
int my_mktemp(char *tmpl);
int xtmpnam_count(void);

static inline int use_compat(char *b)
{
    return my_mktemp(b) + obj.mktemp_flag + xtmpnam_count();
}

#endif
