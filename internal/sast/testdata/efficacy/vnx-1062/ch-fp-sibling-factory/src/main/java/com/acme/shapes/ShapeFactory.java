package com.acme.shapes;

public final class ShapeFactory {
    public static Shape square(double side) {
        return new Square(side);
    }

    public static boolean isSquare(Shape s) {
        return s instanceof Square;
    }
}
