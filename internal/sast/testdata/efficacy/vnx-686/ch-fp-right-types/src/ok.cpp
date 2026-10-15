#include <cstdio>
#include <cstring>
#include <string>

void ok(const char *s)
{
    std::string name = "x";
    int n;
    char buf[32];
    int *p = &n;
    printf("%zu\n", sizeof n);
    printf("%s\n", name.c_str());
    printf("%d\n", (int)strlen(s));
    printf("%f\n", 3.0);
    printf("%c\n", 'a');
    scanf("%d", &n);
    scanf("%31s", buf);
    scanf("%d", p);
}
