#include <cstdio>
#include <string>

void describe(int id)
{
    std::string name = "guest";
    printf("name=%s id=%d\n", name.c_str(), id);
    std::printf("user %s\n", std::to_string(id).c_str());
}
