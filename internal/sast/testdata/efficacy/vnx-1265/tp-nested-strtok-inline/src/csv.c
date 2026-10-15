#include <string.h>

int count_fields(char *text)
{
    int fields = 0;
    char *row;
    for (row = strtok(text, "\n"); row != NULL; row = strtok(NULL, "\n")) {
        char *cell;
~>        cell = strtok(row, ",");
        while (cell) {
            fields++;
            cell = strtok(NULL, ",");
        }
    }
    return fields;
}
