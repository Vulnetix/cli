#ifndef COMPAT_H
#define COMPAT_H
#undef gets
#define gets(s) DO_NOT_USE_gets(s)
char *gets(char *s);
extern char *getwd(char *buf);
#endif
