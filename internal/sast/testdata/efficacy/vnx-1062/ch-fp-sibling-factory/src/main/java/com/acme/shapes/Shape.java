package com.acme.shapes;

public abstract class Shape {
    public abstract double area();

    public Shape scaled(double k) {
        return copyScaled(k);
    }

    protected abstract Shape copyScaled(double k);
}
