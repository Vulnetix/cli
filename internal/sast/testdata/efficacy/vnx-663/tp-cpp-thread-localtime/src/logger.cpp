#include <ctime>
#include <netdb.h>
#include <pwd.h>
#include <string>
#include <thread>

std::string stamp() {
    std::time_t now = std::time(nullptr);
~>    std::tm *tm = std::gmtime(&now);
    char buf[64];
    std::strftime(buf, sizeof buf, "%F %T", tm);
    return buf;
}

std::string owner(uid_t uid) {
~>    struct passwd *pw = getpwuid(uid);
    return pw ? pw->pw_name : "";
}

void resolve(const char *host) {
~>    struct hostent *he = gethostbyname(host);
    use(he);
}

void run() {
    std::thread a(stamp), b(stamp);
    a.join();
    b.join();
}
