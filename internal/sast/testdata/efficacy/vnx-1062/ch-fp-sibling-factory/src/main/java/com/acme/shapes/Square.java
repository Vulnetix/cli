package com.acme.shapes;

public class Square extends Shape {
    private final double side;

    public Square(double side) {
        this.side = side;
    }

    public double area() {
        return side * side;
    }

    protected Shape copyScaled(double k) {
        return new Square(side * k);
    }
}
