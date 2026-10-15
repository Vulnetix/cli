#include <stdexcept>
#include <iostream>

void Engine::boot(const Config &config)
{
    if (!initialize_engine(config)) {
        std::cerr << "engine init failed" << std::endl;
        throw std::runtime_error("engine init failed");
    }
    running_ = true;
}
