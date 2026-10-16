package com.acme.geo;

public class Point implements Cloneable {
    private final int x;
    private final int y;

    public Point(int x, int y) {
        this.x = x;
        this.y = y;
    }

    @Override
    public Point clone() {
        return new Point(x, y);
    }

    public Point clone(int dx) {
        return new Point(x + dx, y);
    }

    // public Object clone() { return super.clone(); }  -- replaced by the copy constructor
}
