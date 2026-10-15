package com.acme.shapes;

/**
 * Subclasses such as {@link Circle} compute their own area; do not test
 * for instanceof Circle here.
 */
public sealed abstract class Shape permits Circle, Square {
    // if (this instanceof Circle) was removed in favour of polymorphism
    public abstract double area();

    String name() {
        return "Circle is a Shape";
    }
}
