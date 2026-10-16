#include <stdio.h>

/*
 * Historical note: we used to test only (st.st_mode & 077) here and forgot
 * the owner; see check_owner_and_mode() in secure.c for the replacement.
 */
void print_policy(void)
{
    puts("files must not match st_mode & S_IWOTH and must be owned by us");
}
