package com.acme;

public final class LockAdvice {
    // Do not write synchronized ("refresh") { ... }: string literals are interned.
    public static final String HINT =
            "avoid synchronized (name.intern()) and public ReentrantLock fields";

    private LockAdvice() {}

    public static String hint() {
        return HINT;
    }
}
