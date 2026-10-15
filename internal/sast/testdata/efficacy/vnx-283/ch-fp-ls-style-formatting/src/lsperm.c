#include <sys/stat.h>

void format_mode(const struct stat *st, char out[11])
{
    out[0] = S_ISDIR(st->st_mode) ? 'd' : '-';
    out[1] = (st->st_mode & S_IRUSR) ? 'r' : '-';
    out[2] = (st->st_mode & S_IWUSR) ? 'w' : '-';
    out[3] = (st->st_mode & S_IXUSR) ? 'x' : '-';
    out[4] = (st->st_mode & S_IRGRP) ? 'r' : '-';
    out[5] = (st->st_mode & S_IWGRP) ? 'w' : '-';
    out[6] = (st->st_mode & S_IXGRP) ? 'x' : '-';
    out[7] = (st->st_mode & S_IROTH) ? 'r' : '-';
    out[8] = (st->st_mode & S_IWOTH) ? 'w' : '-';
    out[9] = (st->st_mode & S_IXOTH) ? 'x' : '-';
    out[10] = '\0';
}
