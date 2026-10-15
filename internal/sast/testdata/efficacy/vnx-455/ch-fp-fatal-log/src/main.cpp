#include <SDL.h>
#include <glog/logging.h>

int main(int argc, char **argv)
{
    google::InitGoogleLogging(argv[0]);
    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        LOG(FATAL) << "SDL_Init failed: " << SDL_GetError();
    }
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
        log_fatal("curl_global_init failed");
    }
    return run();
}
