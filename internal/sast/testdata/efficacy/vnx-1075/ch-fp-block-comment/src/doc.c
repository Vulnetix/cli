#include <stdio.h>

/*
   Do not write retry loops like this:

   again:
       n = read(fd, buf, len);
       if (n < 0 && errno == EINTR)
           goto again;
*/
int noop(void)
{
    return 0;
}
