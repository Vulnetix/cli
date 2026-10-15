#include "state.hpp"

void Machine::step(Signal s) {
  switch (s) {
    case Signal::Start:
      running_ = true;
      return;
~>    case Signal::Pause:
      paused_ = true;
      notify(listeners_);
    case Signal::Stop:
      running_ = false;
      break;
  }
}
