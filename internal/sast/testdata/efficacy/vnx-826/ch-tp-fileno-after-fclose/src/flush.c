#include <stdio.h>
#include <unistd.h>

void finish(FILE *journal)
{
	fflush(journal);
~>	fclose(journal);
	fsync(fileno(journal));
}
