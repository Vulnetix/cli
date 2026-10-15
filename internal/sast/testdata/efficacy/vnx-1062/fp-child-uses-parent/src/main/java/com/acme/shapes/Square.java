package com.acme.shapes;

public class Square extends Shape {
    private final double side = 1;

    @Override
    public double area() {
        Shape s = (Shape) this;
        return side * side;
    }

    public Square copy() {
        return new Square();
    }
}
