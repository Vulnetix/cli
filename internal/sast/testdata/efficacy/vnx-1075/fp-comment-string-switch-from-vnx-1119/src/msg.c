#include <stdio.h>

void show(int code)
{
again:
    switch (code) {
    default:
        break;
    }
    /* goto again; would loop here */
    // goto again;
    puts("use goto again; to retry");
}
