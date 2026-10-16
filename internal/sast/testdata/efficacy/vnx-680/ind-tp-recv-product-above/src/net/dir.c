#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>

struct entry {
    uint64_t inode;
    char name[256];
};

struct entry *read_directory(int sock, uint32_t *n_out)
{
    uint32_t nent;
    if (recv(sock, &nent, sizeof nent, MSG_WAITALL) != sizeof nent) {
        return NULL;
    }
    size_t bytes = nent * sizeof(struct entry);
~>    struct entry *e = malloc(bytes);
    if (!e) {
        return NULL;
    }
    recv(sock, e, bytes, MSG_WAITALL);
    *n_out = nent;
    return e;
}
