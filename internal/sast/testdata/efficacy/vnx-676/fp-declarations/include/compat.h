char *strcpy(char *dst, const char *src);
char *strcat(char *restrict dst, const char *restrict src);
int sprintf(char *str, const char *format, ...);
#define strcpy(d, s) safe_strcpy((d), (s), sizeof(d))
