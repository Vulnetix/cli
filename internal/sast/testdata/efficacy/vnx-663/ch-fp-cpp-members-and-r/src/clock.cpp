#include <thread>
#include <ctime>

struct Clock {
    struct tm *localtime(const time_t *t);
};

void tick(Clock &c, Clock *p) {
    time_t now = time(nullptr);
    struct tm out;
    localtime_r(&now, &out);
    c.localtime(&now);
    p->localtime(&now);
    const char *s = "strtok(buf, \",\")";
    std::thread t([] {});
    t.join();
}
