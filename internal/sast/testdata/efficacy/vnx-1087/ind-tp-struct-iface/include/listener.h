#pragma once

~>struct Listener {
    virtual void onEvent(int code) = 0;
};
