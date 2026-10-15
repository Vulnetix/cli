#include <windows.h>

~>#pragma strict_gs_check(off)

~>__declspec(safebuffers) void copy_name(char *dst, const char *src) {
    lstrcpyA(dst, src);
}
