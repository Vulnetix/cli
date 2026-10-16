#include <stdio.h>
#include <string.h>

void show(const char *name, char *buf, int *p)
{
    size_t len = strlen(name);
    printf("name is %zu bytes\n", strlen(name));
    printf("len=%zu, %lu, %d\n", len, (unsigned long)len, (int)len);
    sprintf(buf, "%s items", "ten");
    char word[32];
    scanf("%31s", word);
    scanf("%d", p);
}
