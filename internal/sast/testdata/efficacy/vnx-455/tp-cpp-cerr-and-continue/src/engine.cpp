#include <iostream>
#include "engine.h"

void Engine::boot(const Config &config)
{
~>    if (!initialize_engine(config)) {
        std::cerr << "engine init failed" << std::endl;
    }
    running_ = true;
    loop();
}
