#include <stdio.h>
#include <string.h>

static int
count_fields (char *record)
{
  int n = 0;
  char *f = strtok (record, ",");
  while (f != NULL)
    {
      n++;
      f = strtok (NULL, ",");
    }
  return n;
}

int
load_config (char *text)
{
  int total = 0;
  char *row = strtok (text, ";");
  while (row != NULL)
    {
~>      total += count_fields (row);
      row = strtok (NULL, ";");
    }
  return total;
}
