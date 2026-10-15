package com.acme.geo;

import java.util.Optional;

public class Geocoder {
    public Optional<Point> locate(String address) {
        try {
            return Optional.of(api.lookup(address));
~>        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public boolean reachable() {
~>        try { return api.ping(); } catch (final Throwable t) { return false; }
    }

    public void refresh() {
        try {
            cache.reload();
~>        } catch (RuntimeException exception) {
            stale = true;
        }
    }
}
