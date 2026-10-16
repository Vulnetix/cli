#include <stdio.h>

/*
 * Never write:
 *     uint32_t count = ntohl(hdr->count);
 *     out = malloc(count * sizeof(struct record));
 * because the product can wrap.
 */
void explain(void)
{
    // int n = atoi(argv[1]); p = malloc(n * sizeof(int));
    puts("p = malloc(atoi(argv[1]) * sizeof(int)) is unsafe");
}
