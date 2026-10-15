#include <string.h>
#include <stdio.h>

#define NAME_LEN 32

struct conf { char name[NAME_LEN]; };

void set_name(struct conf *c, const char *v)
{
    char name[NAME_LEN];
    char small[8];
    char big[64];

    strncpy(name, v, NAME_LEN);
    memset(small, 0, sizeof small);
    snprintf(big, sizeof(big), "%s", v);
    memcpy(small, big, 8);
    fgets(big, 64, stdin);
    // memcpy(small, big, 64);
    memcpy(c->name, name, sizeof(name));
}
