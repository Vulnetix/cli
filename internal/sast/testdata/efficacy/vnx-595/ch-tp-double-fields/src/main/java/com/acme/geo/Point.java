package com.acme.geo;

public class Point {
    private Double lat;
    private Double lon;

    boolean sameLat(Point o) {
        Double theirs = o.lat;
~>        return lat == theirs;
    }
}
