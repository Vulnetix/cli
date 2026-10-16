#include <unistd.h>
#define N 8

int ok(int fd)
{
    char buf[64];
    int arr[N];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0) return -1;
    buf[n] = '\0';
    buf[sizeof(buf) - 1] = '\0';
    for (int i = 0; i < N; i++)
        arr[i] = i;
    int *end = &arr[N];
    (void)end;
    return 0;
}
