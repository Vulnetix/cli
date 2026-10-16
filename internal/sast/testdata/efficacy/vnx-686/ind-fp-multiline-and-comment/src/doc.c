#include <stdio.h>
#include <string.h>

/* printf("%d", strlen(s)) is wrong on LP64 */
void explain(const char *s)
{
    // printf("status %s\n", 404);
    puts("printf(\"%d\", strlen(s)) is wrong");
    printf("%d\n",
           (int)strlen(s));
}
