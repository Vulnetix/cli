#include <stdio.h>

void open_log(void)
{
    FILE *f;
    fopen_s(&f, "log.txt", "w");
}
