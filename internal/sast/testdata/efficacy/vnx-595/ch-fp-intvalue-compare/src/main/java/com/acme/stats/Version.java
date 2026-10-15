package com.acme.stats;

public class Version {
    boolean same(Integer major, Integer otherMajor) {
        // major == otherMajor would compare references
        String msg = "major == otherMajor";
        return major.intValue() == otherMajor.intValue() && !msg.isEmpty();
    }
}
