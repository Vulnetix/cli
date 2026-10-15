package com.example.geo;

public class Point implements Cloneable
{
    protected double x;
    protected double y;

    @Override
~>    protected Object clone()
    {
        Point p = new Point();
        p.x = this.x;
        p.y = this.y;
        return p;
    }
}
