#include <stdio.h>

/* Wrong: if (name == "root") -- compares addresses
 * Wrong: if (flags & MASK == 0)
 */
// total =+ n;   (meant +=)
int main(void)
{
    puts("never write name == \"root\" in C");
    char c = '=';
    return c == '=';
}

int serve_history = 0; /* True for XREADGROUP with ID != ">". */
