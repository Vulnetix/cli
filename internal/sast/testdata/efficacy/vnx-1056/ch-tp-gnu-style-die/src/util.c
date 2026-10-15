#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static void
~>die (int status, const char *format, ...)
{
  va_list ap;
  va_start (ap, format);
  vfprintf (stderr, format, ap);
  va_end (ap);
  exit (status);
}
