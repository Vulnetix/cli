#include <stdio.h>

/*
 * The old implementation used asm volatile("pause") here; it now calls
 * cpu_relax() from the platform layer.
 */
void print_insn(const char *mnemonic)
{
    printf("asm(\"%s\")\n", mnemonic);
    puts("__asm__ __volatile__ is not emitted by this tool");
}
