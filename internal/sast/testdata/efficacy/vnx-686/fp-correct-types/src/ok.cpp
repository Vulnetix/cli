#include <cstdio>
#include <cstring>
#include <string>

void ok(const std::string &name, const char *s, int code, size_t n, char *buf) {
    int count;
    char word[16];
    int *out = &count;
    printf("name is %zu bytes\n", strlen(s));
    printf("%s=%d\n", name.c_str(), code);
    printf("%s\n", s);
    printf("%lu\n", (unsigned long)sizeof(buf));
    printf("%c\n", 'y');
    printf("%f\n", 1.0);
    printf("%d\n", 404);
    printf("%s\n", "literal");
    printf("%*s|\n", 10, s);
    snprintf(buf, n, "%zd", n);
    scanf("%d", &count);
    scanf("%15s", word);
    scanf("%d", out);
    printf("%s %d\n", s);
}
