package com.example.geo;

public class LatLng {
    private final double lat;
    private final double lng;

    public LatLng(double lat, double lng) {
        this.lat = lat;
        this.lng = lng;
    }

    @Override
~>    public boolean equals(
            final Object other)
    {
        if (!(other instanceof LatLng)) {
            return false;
        }
        LatLng o = (LatLng) other;
        return Double.compare(lat, o.lat) == 0 && Double.compare(lng, o.lng) == 0;
    }

    @Override
    public String toString() {
        return lat + "," + lng;
    }
}
