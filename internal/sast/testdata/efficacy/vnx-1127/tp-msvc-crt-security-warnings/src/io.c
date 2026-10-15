#ifdef _MSC_VER
~>#define _CRT_SECURE_NO_WARNINGS
~>#pragma warning(disable: 4996)
~>#  pragma warning( disable : 4127 4996 )
#endif
#include <stdio.h>
#include <string.h>

void copy_name(char *dst, const char *src) {
    strcpy(dst, src);
}
