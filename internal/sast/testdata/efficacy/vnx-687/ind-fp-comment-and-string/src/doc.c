#include <stdio.h>

/* mkdir(dir, 755) is decimal; fopen(path, "rw") is not a mode */
void explain(void)
{
    // strncat(full, file, sizeof(full));
    puts("never call mkdir(dir, 755)");
}
