package com.acme.sort;

public class Version implements Comparable<Version> {
    private final int major;

    public Version(int major) {
        this.major = major;
    }

    @Override
    public int compareTo(Version o) {
        return Integer.compare(major, o.major);
    }

    public boolean same(Version o) {
        return compareTo(o) == 0;
    }

    public boolean older(Version o) {
        return this.compareTo(o) < 0 || o.compareTo(this) > 0;
    }

    public boolean single(java.util.List<String> parts) {
        return parts.size() == 1 || parts.indexOf("x") == -1;
    }
}
