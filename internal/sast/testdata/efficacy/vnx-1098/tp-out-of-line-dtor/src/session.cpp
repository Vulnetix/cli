#include "session.h"

Session::Session(const std::string& user) : user_(new std::string(user)) {}

~>Session::~Session()
{
    delete user_;
}

Session& Session::operator=(const Session& other) {
    *user_ = *other.user_;
    return *this;
}
