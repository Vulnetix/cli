#include <stdio.h>
#include <fcntl.h>

void fmt(int width, int n, int len, const char *s, double f, const char *path)
{
    int x;
    printf("100%% done\n");
    printf("%*d\n", width, n);
    printf("%.*s\n", len, s);
    printf("%-5s|%5.2f\n", s, f);
    sscanf(s, "%*d %d", &x);
    int a = open(path, O_RDONLY);
    int b = open(path, O_CREAT | O_WRONLY, 0644);
    (void)a; (void)b;
}
