#include "session.hpp"

struct Session::State {
    virtual ~State() {}
    virtual void enter(Session& s) const {}
    virtual bool expired(Session& s) const { return true; }
};
