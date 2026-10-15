#include <stdlib.h>
#include <string.h>

char board[9][10];

void load_row(int r, char *line)
{
    char *tok = strtok(line, ",");
    for (int c = 0; tok != NULL && c < 9; c++) {
~>        board[r][c] = atoi(tok);
        tok = strtok(NULL, ",");
    }
}
