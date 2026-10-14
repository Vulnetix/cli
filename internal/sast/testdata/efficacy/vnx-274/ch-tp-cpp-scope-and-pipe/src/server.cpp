#include <iostream>
#include <unistd.h>
#include <windows.h>

#include "server.h"

void Server::demote()
{
~>    if (::setuid(uid_) != 0) {
        std::cerr << "warning: could not drop to uid " << uid_ << '\n';
    }
    run();
}

void Server::onClient(HANDLE pipe)
{
~>    if (!ImpersonateNamedPipeClient(pipe)) {
        log_->warn("impersonation failed: %lu", GetLastError());
    }
    handleRequest(pipe);
    RevertToSelf();
}
