package com.acme.shapes;

public abstract class Shape {
    public abstract double area();

    public boolean isText(Object o) {
        CircleRenderer r = new CircleRenderer();
        return o instanceof String || o instanceof CircleRenderer;
    }
}
