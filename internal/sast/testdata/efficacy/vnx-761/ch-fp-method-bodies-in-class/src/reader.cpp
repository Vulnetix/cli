#include <cstdlib>

class Reader {
public:
    char *scan()
    {
        char *line = static_cast<char *>(std::malloc(128));
        line++;
        return line - 1;
    }

    void release(char *line)
    {
        std::free(line);
    }
};
