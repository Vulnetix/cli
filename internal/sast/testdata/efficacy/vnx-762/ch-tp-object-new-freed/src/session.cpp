#include <cstdlib>
#include <string>

struct Session {
    std::string user;
};

void end_session()
{
    Session *s = new Session();
    s->user = "guest";
~>    free(s);
}

void end_many()
{
    Session *one = new Session;
~>    delete[] one;
}
