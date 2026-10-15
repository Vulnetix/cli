package com.acme;

import java.util.Objects;

/**
 * @throws NullPointerException if name is null
 */
public class Guard {
    public Guard(String name) {
        Objects.requireNonNull(name, "name");
        if (name.isEmpty()) {
            throw new NullPointerException("empty name");
        }
    }

    public void handle(Exception e) {
        if (e instanceof NullPointerException) {
            report(e);
        }
        try {
            parse();
        } catch (NullPointerExceptionWrapper w) {
            report(w);
        }
    }
}
