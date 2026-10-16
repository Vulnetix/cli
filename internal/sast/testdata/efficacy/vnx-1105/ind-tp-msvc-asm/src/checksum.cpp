#include <windows.h>

int cpu_has_cpuid(void)
{
    int r = 0;
~>    __asm {
        mov eax, 1
        cpuid
        mov r, edx
    }
    return r;
}
