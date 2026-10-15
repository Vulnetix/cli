#include <new>
#include "value.h"

Value& Value::operator=(const Value& other) {
    if (this != &other) {
~>        this -> ~Value ();
        new (this) Value(other);
    }
    return *this;
}
