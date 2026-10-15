#include <stdlib.h>
#include <time.h>
#include <unistd.h>

void new_session_id(char *session_id, size_t n)
{
~>    srand((unsigned) time(NULL) ^ getpid());
    for (size_t i = 0; i + 1 < n; i++)
        session_id[i] = 'a' + rand() % 26;
    session_id[n - 1] = '\0';
}
