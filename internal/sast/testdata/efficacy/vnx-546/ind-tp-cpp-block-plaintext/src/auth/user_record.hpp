#pragma once
#include <string>

/*
 * Cached user record shared between the login and profile modules.
~> * TODO: the password is held here in plain text; hash it before caching.
 */
struct UserRecord {
    std::string name;
    std::string password;
};
