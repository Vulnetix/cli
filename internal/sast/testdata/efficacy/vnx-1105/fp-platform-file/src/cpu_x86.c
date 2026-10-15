#include <stdint.h>

void cpu_relax(void)
{
    __asm__ __volatile__("pause");
}
