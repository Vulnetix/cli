#include <cstdlib>
#include <unistd.h>

class Runner {
public:
    void read_as(uid_t uid) {
        if (seteuid(uid) != 0)
            throw std::runtime_error("seteuid");
        load_config();
        if (seteuid(0) != 0)
            abort();
    }

    void lower(uid_t uid) {
        seteuid(uid);
    }

    int run_hook(const char *hook) {
        return std::system(hook);
    }
};
