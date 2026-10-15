#include <stdio.h>
#include <stdlib.h>

void render_form(struct page *p)
{
    char csrf_token[17];
    snprintf(csrf_token, sizeof csrf_token,
~>             "%08x%08x", (unsigned) rand(), (unsigned) rand());
    page_set_hidden(p, "csrf", csrf_token);
}
