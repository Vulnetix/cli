#include <cstdio>
#include <cstring>
#include <string>

void ok(const char *name, char *buf, int id)
{
    std::string s = "x";
    size_t len = strlen(name);
    double ratio = 0.5;
    int count = 0;
    char word[32];
    printf("name is %zu bytes\n", strlen(name));
    printf("len=%zu %lu\n", len, (unsigned long)len);
    printf("ratio=%f\n", ratio);
    printf("%d\n", (int)strlen(name));
    printf("name=%s\n", s.c_str());
    scanf("%d", &count);
    scanf("%31s", word);
    sprintf(buf, "%s %d", name, id);
}
