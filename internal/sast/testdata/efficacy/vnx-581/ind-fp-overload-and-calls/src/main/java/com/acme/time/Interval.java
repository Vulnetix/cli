package com.acme.time;

import java.util.HashMap;
import java.util.Map;

public class Interval {
    private final long start;
    private final long end;
    private final Map<String, String> tags = new HashMap<>();

    public Interval(long start, long end) {
        this.start = start;
        this.end = end;
    }

    public boolean equals(Interval other) {
        return other != null && start == other.start && end == other.end;
    }

    public int tagHash() {
        return tags.hashCode();
    }

    public boolean sameTags(Interval other) {
        return tags.equals(other.tags);
    }
}
