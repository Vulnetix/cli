#include <stdio.h>

void finish(FILE *log, int rows)
{
    fflush(log);
    fclose(log);
~>    fprintf(log, "wrote %d rows\n", rows);
}
