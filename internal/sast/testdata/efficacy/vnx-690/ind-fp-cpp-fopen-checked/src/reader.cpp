#include <cstdio>
#include <cstdlib>

bool read_header(const char *path, char *out)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return false;
    }
    fgets(out, 128, fp);
    fclose(fp);
    char *tmp = (char *)malloc(16);
    assert(tmp);
    tmp[0] = 0;
    free(tmp);
    return true;
}
