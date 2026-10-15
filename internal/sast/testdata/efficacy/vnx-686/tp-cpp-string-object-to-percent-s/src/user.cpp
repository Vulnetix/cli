#include <cstdio>
#include <string>

void User::print(const std::string &name, int id) {
~>    std::printf("user %s\n", std::to_string(id));
~>    printf("name=%s id=%d\n", name, id);
~>    printf("[%s]\n", out.str());
}
