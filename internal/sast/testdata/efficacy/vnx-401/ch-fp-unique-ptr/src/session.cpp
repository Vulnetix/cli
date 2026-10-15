#include <memory>

bool Server::accept_one(int fd)
{
    auto session = std::make_unique<Session>(fd);
    if (!session->handshake()) {
        return false;
    }
    sessions_.push_back(std::move(session));
    return true;
}
