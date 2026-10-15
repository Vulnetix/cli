#include <stdint.h>
#include <stdlib.h>

uint8_t parse_level(const char *arg)
{
~>    uint8_t level = (uint8_t)strtoul(arg, NULL, 10);
    return level;
}
