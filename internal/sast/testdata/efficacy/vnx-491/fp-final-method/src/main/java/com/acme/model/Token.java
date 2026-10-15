package com.acme.model;

public class Token implements Cloneable {
    @Override
    public final Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

    public final Token clone2() {
        return new Token();
    }
}
