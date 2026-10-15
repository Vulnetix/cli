package com.example.cache;

import java.util.Objects;

public class Cache {
    private final String region;

    public Cache(String region) {
        this.region = region;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof Cache && ((Cache) other).region.equals(region);
    }

    @Override
    public int hashCode() {
        return region.hashCode();
    }

    static final class Key {
        final String a;
        final int b;

        Key(String a, int b) {
            this.a = a;
            this.b = b;
        }

        @Override
~>        public final boolean equals(final Object obj) {
            if (!(obj instanceof Key)) {
                return false;
            }
            Key k = (Key) obj;
            return Objects.equals(a, k.a) && b == k.b;
        }
    }
}
