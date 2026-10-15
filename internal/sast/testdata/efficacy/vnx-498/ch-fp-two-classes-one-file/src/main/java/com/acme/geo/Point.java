package com.acme.geo;

public class Point implements Cloneable {
    private int x;
    private int y;

    @Override
    public Point clone() throws CloneNotSupportedException {
        return (Point) super.clone();
    }
}

class Account {
    private String password;
    private String apiKey;
}
