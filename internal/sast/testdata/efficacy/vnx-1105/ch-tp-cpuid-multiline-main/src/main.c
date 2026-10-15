#include <stdio.h>

int main(int argc, char **argv)
{
    unsigned int eax = 1, ebx, ecx, edx;
~>    asm volatile(
        "cpuid"
        : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        :
        : "memory");
    if (ecx & (1u << 28))
        puts("avx available");
    return 0;
}
