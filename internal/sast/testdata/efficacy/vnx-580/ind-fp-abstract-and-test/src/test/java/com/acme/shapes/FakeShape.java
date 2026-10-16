package com.acme.shapes;

public class FakeShape implements Cloneable {
    @Override
    public FakeShape clone() {
        return new FakeShape();
    }
}
