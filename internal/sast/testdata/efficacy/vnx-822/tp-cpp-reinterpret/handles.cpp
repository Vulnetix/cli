#include <cstdint>
#include <string>

void close_handle(const Request &req) {
~>    auto *obj = reinterpret_cast<Widget *>(std::stoull(req.param("handle")));
    obj->close();
    std::uintptr_t raw = std::stoull(req.param("ctx"));
~>    Context *ctx = reinterpret_cast<Context *>(raw);
    ctx->reset();
}
