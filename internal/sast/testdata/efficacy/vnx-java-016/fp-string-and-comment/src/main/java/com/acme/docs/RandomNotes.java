package com.acme.docs;

public class RandomNotes {
    // Do not use new Random().nextLong() for a session token.
    static final String ADVICE = "Math.random() must never generate a password";

    String advice() {
        return ADVICE;
    }
}
