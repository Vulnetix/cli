// #pragma warning(disable: 4996)
/* #pragma GCC diagnostic ignored "-Wformat-security" */
#include <stdio.h>
static const char *hint = "#define _CRT_SECURE_NO_WARNINGS is not used here";
void show(void) { puts(hint); }
