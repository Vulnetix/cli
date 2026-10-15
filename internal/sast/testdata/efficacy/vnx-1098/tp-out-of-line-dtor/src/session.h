#pragma once
#include <string>

class Session {
public:
    Session(const std::string& user);
    virtual ~Session();
    Session& operator=(const Session& other);

private:
    std::string* user_;
};
