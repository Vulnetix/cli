#include <string.h>

struct bucket { int key; int value; };

void sift(struct bucket *array, size_t start, size_t child, const char *name)
{
    memcpy(&array[start], &array[child], sizeof(struct bucket));
    register_name(name, strlen(name), NULL);
    lookup(strlen(name), NULL);
}
