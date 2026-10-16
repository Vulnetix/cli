#include <stdio.h>
#include <immintrin.h>

/* previously used asm volatile("pause") here; now a wrapper */
const char *msg = "asm(\"nop\") is not allowed in this file";
int asm_count = 0;

void spin(void)
{
    _mm_pause();
    cpu_relax();
    asm_count++;
    puts(msg);
}
