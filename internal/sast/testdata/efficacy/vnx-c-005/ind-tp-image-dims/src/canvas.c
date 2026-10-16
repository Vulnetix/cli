#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: canvas WIDTH HEIGHT\n");
        return 1;
    }
    int width = atoi(argv[1]);
    int height = (int)strtol(argv[2], NULL, 10);
    size_t bytes = width * height * sizeof(unsigned int);
~>    unsigned int *pixels = malloc(bytes);
    if (pixels == NULL)
        return 1;
    for (int i = 0; i < width * height; i++)
        pixels[i] = 0xff000000u;
    free(pixels);
    return 0;
}
