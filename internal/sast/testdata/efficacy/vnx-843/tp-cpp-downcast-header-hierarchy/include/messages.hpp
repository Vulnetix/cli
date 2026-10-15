#pragma once
#include <string>

struct Message {
    virtual ~Message() = default;
    int type = 0;
};

struct LoginMessage : Message {
    std::string user;
    std::string password;
};

struct ChatMessage : public Message {
    std::string text;
};
