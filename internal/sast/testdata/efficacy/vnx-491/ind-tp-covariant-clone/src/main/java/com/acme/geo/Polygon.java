package com.acme.geo;

import java.util.ArrayList;
import java.util.List;

public class Polygon implements Cloneable {
    private List<Point> points = new ArrayList<>();

    @Override
~>    public Polygon clone() {
        try {
            Polygon copy = (Polygon) super.clone();
            copy.points = new ArrayList<>(points);
            return copy;
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(e);
        }
    }
}
