package com.acme.geo;

public class Shape implements Cloneable {
    private double[] points;

~>    @Override public Shape clone() {
        try {
            Shape s = (Shape) super.clone();
            s.points = points.clone();
            return s;
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(e);
        }
    }
}
