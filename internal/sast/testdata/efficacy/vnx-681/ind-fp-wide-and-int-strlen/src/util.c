#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

void print_name(const char *s)
{
    int len = strlen(s);
    size_t n = strlen(s);
    uint32_t wire_len = strlen(s);
    printf("%.*s (%d, %zu, %u)\n", (int)strlen(s), s, len, n, wire_len);
}

long file_size(FILE *fp)
{
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    off_t end = lseek(fileno(fp), 0, SEEK_END);
    return sz > end ? sz : (long)end;
}
