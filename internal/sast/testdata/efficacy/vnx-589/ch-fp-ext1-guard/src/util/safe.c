#define @@sample:[_][_]ST[D]C[_][W]AN[T][_]L[I]B[_][E]XT[1][_][_]@@ 1
#include <string.h>

void copy(char *dst, size_t n, const char *src)
{
#if defined(__STDC_LIB_EXT1__)
    strcpy_s(dst, n, src);
#else
    snprintf(dst, n, "%s", src);
#endif
}
