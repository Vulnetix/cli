#include <csignal>
#include <cstdio>

class Server {
public:
    static void OnSignal(int sig);
    static Server *instance;
    void Shutdown();
};

Server *Server::instance = nullptr;

void Server::OnSignal(int sig)
{
    std::printf("signal %d, shutting down\n", sig);
    instance->Shutdown();
}

void InstallHandlers()
{
~>    std::signal(SIGINT, &Server::OnSignal);
~>    std::signal(SIGTERM, Server::OnSignal);
}
