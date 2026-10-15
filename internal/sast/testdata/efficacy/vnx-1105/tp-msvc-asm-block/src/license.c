#include <windows.h>

int check_license(const char *key)
{
    int cpu = 0;
~>    __asm {
        mov eax, 1
        cpuid
        mov cpu, eax
    }
~>    __asm mov eax, cpu
    return validate(key, cpu);
}
