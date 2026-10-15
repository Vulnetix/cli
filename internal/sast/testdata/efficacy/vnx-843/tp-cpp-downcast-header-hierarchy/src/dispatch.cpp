#include "messages.hpp"

void handle_login(const std::string &user, const std::string &password);

void on_message(Message *msg)
{
    // The sender chose the concrete type; nothing here checks it.
~>    auto *login = static_cast<LoginMessage *>(
        msg);
    handle_login(login->user, login->password);
}
