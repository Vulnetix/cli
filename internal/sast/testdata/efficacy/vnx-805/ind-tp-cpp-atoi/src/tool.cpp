#include <cstring>
#include <cstdlib>

int main(int argc, char **argv)
{
    char out[32];
    const char *src = argv[1];
~>    std::memcpy(out, src, std::atoi(argv[2]));
    return out[0];
}
