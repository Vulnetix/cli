package com.bank.util;

public class Checks {
    enum State { OPEN, CLOSED }

    boolean open(State s, Integer code, int expected) {
        if (code == null || s == State.OPEN) {
            return false;
        }
        Integer cached = lookup();
        if (cached != null && cached == expected) {
            return true;
        }
        return this == other();
    }

    Integer lookup() { return 1; }
    Object other() { return null; }
}
