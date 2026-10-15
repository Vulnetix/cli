#include <signal.h>
#include <stdlib.h>

static char *state;

static void
shutdown_handler (int sig)
{
  free (state);
  state = NULL;
  exit (0);
}

int
main (void)
{
  state = malloc (128);
~>  signal (SIGINT, shutdown_handler);
~>  signal (SIGTERM, shutdown_handler);
  for (;;)
    ;
}
