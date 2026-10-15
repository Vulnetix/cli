#include <string>

void Store::save(const std::string &user, const std::string &pw) {
~>    // XXX: password stored in plain text for now
    db_.put(user, pw);
}
