#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static char *pending;

static void
on_term (int sig)
{
~>  fprintf (stderr, "terminating on %d\n", sig);
~>  free (pending);
~>  exit (EXIT_FAILURE);
}

int
main (void)
{
  signal (SIGTERM, on_term);
  pending = malloc (64);
  for (;;)
    ;
}
