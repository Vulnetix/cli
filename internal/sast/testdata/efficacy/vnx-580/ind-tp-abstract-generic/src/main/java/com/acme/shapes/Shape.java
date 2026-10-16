package com.acme.shapes;

import java.util.ArrayList;
import java.util.List;

public abstract class Shape<T extends Number> implements Cloneable {
    protected List<T> points = new ArrayList<>();

    public abstract double area();

    @Override
~>    public Shape<T> clone()
    {
        Shape<T> copy = newInstance();
        copy.points = new ArrayList<>(points);
        return copy;
    }

    protected abstract Shape<T> newInstance();
}
