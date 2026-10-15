#include "session.h"

void Session::onEvent(Event ev) {
    switch (ev.kind) {
        case Kind::Login: {
            authenticated_ = true;
            break;
        }
~>        case Kind::Logout: {
            authenticated_ = false;
            tokens_.clear();
        }
        case Kind::Ping:
            touch();
            break;
    }
}
