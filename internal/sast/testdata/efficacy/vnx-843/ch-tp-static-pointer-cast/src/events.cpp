#include <memory>
#include <string>

struct Event {
    virtual ~Event() = default;
    int id = 0;
};

struct KeyEvent : public Event {
    int keycode = 0;
};

struct MouseEvent : public Event {
    int x = 0, y = 0;
};

int key_of(const std::shared_ptr<Event> &ev)
{
~>    auto k = std::static_pointer_cast<KeyEvent>(ev);
    return k->keycode;
}
