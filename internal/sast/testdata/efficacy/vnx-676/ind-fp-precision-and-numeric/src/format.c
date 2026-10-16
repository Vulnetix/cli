#include <stdio.h>

void fmt(char *out, const char *name, int a, double b)
{
    char word[16];
    sprintf(out, "%d items at %.2f", a, b);
    sprintf(out, "name=%.20s", name);
    scanf("%15s", word);
    sscanf(name, "%*s %d", &a);
}
