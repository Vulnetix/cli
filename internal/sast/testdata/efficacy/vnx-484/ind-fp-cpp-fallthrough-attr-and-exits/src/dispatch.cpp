#include <stdexcept>
#include "dispatch.hpp"

int Dispatcher::run(Command cmd) {
    for (auto& job : jobs_) {
        switch (job.kind) {
            case Kind::Skip:
                continue;
            case Kind::Warm:
                cache_.prime(job.key);
                [[fallthrough]];
            case Kind::Load:
                cache_.load(job.key);
                break;
            case Kind::Fatal:
                throw std::runtime_error("fatal job");
            case Kind::Jump:
                goto done;
            default:
                return -1;
        }
    }
done:
    // switch (x) { case 1: a(); case 2: b(); }   -- example from the style guide
    const char* help = "switch (m) { case 1: go(); case 2: stop(); }";
    log_.info(help);
    return 0;
}
