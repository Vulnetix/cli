#include "handlers.h"

void dispatch(const Message &msg)
{
    Handler *handler = nullptr;
    switch (msg.type())
    {
    case MessageType::Ping:
        handler = &ping_handler;
        break;
    case MessageType::Data:
        handler = &data_handler;
        break;
    }
    if (handler != nullptr)
        handler->run(msg);
}
