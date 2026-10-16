#include <string>

struct B { void strcpy(const char *); char *gets(); };

void my_strcpy(char *d, const char *s);
char *gets(char *);

void f(B &b, B *p, const char *s) {
    b.strcpy(s);
    p->gets();
    my_strcpy(nullptr, s);
    // gets(buf); strcpy(a, b);
    const char *msg = "never call gets(x) or strcpy(a, b)";
    (void)msg;
}
