package com.acme.geo;

public class Point implements Cloneable {
    private double x;
    private double y;
    private String label;
    private int passwordLength;

    @Override
    public Point clone() throws CloneNotSupportedException {
        return (Point) super.clone();
    }
}
