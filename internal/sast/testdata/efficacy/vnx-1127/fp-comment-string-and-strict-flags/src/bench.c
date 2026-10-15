#include <stdio.h>

/* Do not add #pragma warning(disable: 4996) here; use strcpy_s. */
// #define _CRT_SECURE_NO_WARNINGS
static const char *hint = "run 'sudo sysctl -w net.inet.tcp.msl=1000' first";
static const char *flags = "-w";

int main(void) {
    printf("%s %s\n", hint, flags);
    return 0;
}
