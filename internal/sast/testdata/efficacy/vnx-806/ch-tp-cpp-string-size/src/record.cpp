#include <cstring>
#include <string>

struct Record { char user[32]; char note[64]; };

void fill(Record &r, const std::string &user, const std::string &note)
{
~>    std::memcpy(r.user, user.c_str(), user.size() + 1);
~>    strncpy(r.note, note.data(), note.length());
}
