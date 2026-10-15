#include <asm/unistd.h>
#include <asm/byteorder.h>
#include <sys/syscall.h>
#include "wasm_loader.h"

static int plasma_asm_count;

long my_gettid(void)
{
    plasma_asm_count++;
    wasm_module_load("core.wasm");
    return syscall(__NR_gettid);
}
