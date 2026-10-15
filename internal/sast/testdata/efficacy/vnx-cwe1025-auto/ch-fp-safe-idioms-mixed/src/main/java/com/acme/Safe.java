package com.acme;

public class Safe {

    enum State { OPEN, CLOSED }

    public boolean check(String name, State state, Integer count, int limit, char c) {
        if (name == null || name.trim().length() == 0) {
            return false;
        }
        if ("admin".equals(name) || name.equalsIgnoreCase("root")) {
            return true;
        }
        if (state == State.OPEN && c == 'y') {
            return true;
        }
        if (count != null && count == limit) {
            return true;
        }
        if (this.getClass() == Safe.class) {
            return true;
        }
        log("comparison name == \"admin\" is wrong");
        return false;
    }

    private void log(String s) {
        int level = 3;
        int other = 4;
        if (level == other) {
            System.out.println(s);
        }
    }
}
