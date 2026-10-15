package com.acme.plugins;

public class Notes {
    // never do obj.getClass().getName().equals("x") for trust decisions
    /* obj.getClass().getName() == "y" */
    static final String HINT = "use instanceof, not getClass().getName().equals(\"Foo\")";
    boolean eq(String a) {
        return a == "literal";
    }
}
