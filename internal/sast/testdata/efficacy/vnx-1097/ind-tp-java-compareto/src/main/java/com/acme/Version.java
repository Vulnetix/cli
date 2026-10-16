package com.acme;

public final class Version implements Comparable<Version> {
    private final int major;
    private final int minor;

    public Version(int major, int minor) {
        this.major = major;
        this.minor = minor;
    }

    @Override
~>    public int compareTo(Version other) {
        int c = Integer.compare(major, other.major);
        return c != 0 ? c : Integer.compare(minor, other.minor);
    }
}
