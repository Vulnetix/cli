#include <string.h>
#include <unistd.h>

int is_elf(int fd)
{
    unsigned char hdr[16];
    if (read(fd, hdr, sizeof(hdr)) != sizeof(hdr))
        return 0;
    return memcmp(hdr, "\x7f" "ELF", 4) == 0;
}
