#include <string.h>

/* We used to call asm("pause") here; see cpu_x86.c instead. */
// __asm__ volatile("mfence");
static const char *kw = "asm(";

int is_asm_keyword(const char *t)
{
    int has_asm = strcmp(t, "asm") == 0;
    int plasma(int x);
    return has_asm || strcmp(t, kw) == 0;
}
