#ifndef COMPAT_H
#define COMPAT_H

/* Ban the unsafe functions so new code cannot call them. */
char *strcpy(char *restrict dest, const char *src) __attribute__((deprecated("use safe_strlcpy instead")));
char *strcat(char *restrict dest, const char *restrict src) __attribute__((deprecated("use safe_strlcat instead")));
extern char *gets (char *__s);
int sprintf(char *str, const char *format, ...) __attribute__((deprecated));
#define strcpy(d, s) safe_strlcpy((d), (s), sizeof(d))

#endif
