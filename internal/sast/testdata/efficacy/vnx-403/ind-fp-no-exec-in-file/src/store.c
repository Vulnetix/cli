#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

struct store {
    int data_fd;
    FILE *journal;
};

int store_open(struct store *s, const char *data_path, const char *journal_path)
{
    s->data_fd = open(data_path, O_RDWR | O_CREAT, 0600);
    if (s->data_fd < 0)
        return -1;
    s->journal = fopen(journal_path, "a");
    if (!s->journal)
        return -1;
    return 0;
}

ssize_t store_read_page(struct store *s, void *buf, size_t n, off_t off)
{
    return pread(s->data_fd, buf, n, off);
}
