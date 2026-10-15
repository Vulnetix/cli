#include <string.h>

int match_routes(char *routes, const char *want)
{
    int hits = 0;
    char *route = strtok(routes, " ");
    while (route)
    {
~>        char *seg = strtok(route, "/");
        if (seg && strcmp(seg, want) == 0)
        {
            hits++;
        }
        route = strtok(NULL, " ");
    }
    return hits;
}
