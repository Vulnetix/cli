#include <memory>
#include "handlers.hpp"

Response Router::dispatch(const Request &req)
{
    Handler *h = nullptr;
~>    switch (req.method()) {
        case Method::Get:
            h = &get_handler_;
            break;
        case Method::Post:
            h = &post_handler_;
            break;
    }
    return h->handle(req);
}
