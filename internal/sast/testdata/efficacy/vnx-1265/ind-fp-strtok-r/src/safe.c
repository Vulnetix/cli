#include <string.h>

void walk(char *text)
{
    char *outer, *inner;
    char *row = strtok_r(text, "\n", &outer);
    while (row) {
        char *cell = strtok_r(row, ",", &inner);
        while (cell) {
            cell = strtok_r(NULL, ",", &inner);
        }
        row = strtok_r(NULL, "\n", &outer);
    }
}
