package com.acme.shapes;

public abstract class Shape {
    public abstract double area();

    public String describe() {
~>        if (this instanceof Circle) {
            return "round";
        }
        return "polygon";
    }
}
