package com.acme.util;

import java.io.Serializable;

/**
 * Tasks that implements Serializable must declare a serialVersionUID.
 */
public class Tasks {
    // class Job implements Serializable {
    private final Runnable job = (Runnable & Serializable) () -> System.out.println("x");

    String doc() {
        return "class Foo implements Serializable {";
    }
}
