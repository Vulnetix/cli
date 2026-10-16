#include <string.h>
#include <stddef.h>

size_t first_word_len(const char *line)
{
    const char *end = strchr(line, ' ');
    if (end == NULL)
        return strlen(line);
    return end - line;
}
