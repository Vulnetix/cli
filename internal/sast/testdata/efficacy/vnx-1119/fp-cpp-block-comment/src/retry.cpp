#include <cerrno>

/*
   The old loop, kept for reference:

   again:
       n = ::read(fd, buf, len);
       if (n < 0 && errno == EINTR)
           goto again;
*/
int Reader::fill()
{
    return 0;
}
