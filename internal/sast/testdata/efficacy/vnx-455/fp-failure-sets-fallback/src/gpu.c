#include <stdio.h>

void choose_backend(void)
{
    if (gpu_init() != 0) {
        fprintf(stderr, "gpu init failed, using cpu\n");
        use_cpu_backend = 1;
    }
}
