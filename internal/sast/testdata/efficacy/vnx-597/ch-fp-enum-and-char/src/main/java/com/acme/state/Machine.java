package com.acme.state;

public class Machine {
    enum State { OPEN, CLOSED }

    boolean check(State state, char c, Object o) {
        String name = "x";
        return state == State.OPEN && c == 'a' && o == this && name.isEmpty();
    }
}
