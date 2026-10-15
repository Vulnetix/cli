package com.acme.model;

public class Point {
    private int x, y;

    public Point copy() {
        return new Point(x, y);
    }

    public Point clone() {
        return new Point(x, y);
    }

    protected Object clone(int depth) {
        return this;
    }
}
