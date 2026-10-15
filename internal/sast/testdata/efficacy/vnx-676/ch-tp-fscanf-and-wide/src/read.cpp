#include <cstdio>
#include <cwchar>

void load(FILE *fp, wchar_t *dst, const wchar_t *src)
{
    char name[32];
    int age;
~>    fscanf(fp, "%s %d", name, &age);
~>    std::wcscpy(dst, src);
}
