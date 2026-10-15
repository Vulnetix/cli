package com.acme.geo;

public class Route
        implements Cloneable, Serializable {

    @Override
~>    public Route clone()
            throws CloneNotSupportedException
    {
        Route r = (Route)
                super.clone();
        return r;
    }
}
