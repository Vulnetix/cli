package com.acme.shapes;

public abstract class Shape {
    public abstract double area();

    public boolean sameKind(Object other) {
        return other instanceof Shape && other.getClass() == getClass();
    }
}
