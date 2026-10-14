#include <stdio.h>
#include <stdlib.h>

#define SAFE_FREE(p) do { free(p); (p) = NULL; } while (0)
#define FREE_AND_LOG(p) \
    free(p);            \
    log_freed(p)

/* Never write free(p); p->x = 1; it is a use-after-free.
 * free(q);
 * q->next = NULL;
 */
void help(void)
{
    // free(ptr);
    // ptr->len = 0;
    puts("call free(ptr); then never touch ptr->len");
    printf("free(item) then item->next\n");
}
