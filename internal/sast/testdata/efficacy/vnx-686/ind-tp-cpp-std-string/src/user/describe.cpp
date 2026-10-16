#include <cstdio>
#include <string>

void describe(int id)
{
    std::string name = "guest";
~>    printf("name=%s id=%d\n", name, id);
~>    std::printf("user %s\n", std::to_string(id));
}
