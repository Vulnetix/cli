#include <stdio.h>

void finish(int fd, FILE *fp)
{
#ifdef _WIN32
    _close(fd);
    fclose(fp);
#else
    fclose(fp);
#endif
}
