#include <string.h>

void walk(char *text)
{
    char *row, *cell;
    for (row = strtok(text, "\n"); row; row = strtok(NULL, "\n")) {
~>        cell = strtok(row, ",");
        while (cell) {
            cell = strtok(NULL, ",");
        }
    }
}
