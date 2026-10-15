package com.acme;

import java.util.Objects;

public class Version implements Comparable<Version> {
    private final int major;

    public Version(int major) {
        this.major = major;
    }

    public int compareTo(Version other) {
        return Integer.compare(major, other.major);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Version v && v.major == major;
    }

    @Override
    public int hashCode() {
        return Objects.hash(major);
    }
}

record Point(int x, int y) implements Comparable<Point> {
    public int compareTo(Point o) {
        return Integer.compare(x, o.x);
    }
}

class SemVer extends Version {
    SemVer(int m) {
        super(m);
    }

    public int compareTo(Version other) {
        return super.compareTo(other);
    }
}
