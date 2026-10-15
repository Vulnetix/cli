package com.acme.model;

import java.io.Serializable;

public interface Identified extends Serializable {
    long id();
}

enum Status implements Serializable {
    OPEN, CLOSED
}

record Money(long cents, String currency) implements Serializable {
}
