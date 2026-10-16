#include "session.h"

Session::Session(User* u) : user_(u) {}

~>Session::~Session()
{
    delete user_;
}

void Session::touch() { ++hits_; }
