package com.example.shape;

public abstract class Shape implements Cloneable {
    protected double x;
    protected double y;

    @Override
~>    public Shape clone() {
        Shape s = copy();
        s.x = x;
        s.y = y;
        return s;
    }

    protected abstract Shape copy();
}
