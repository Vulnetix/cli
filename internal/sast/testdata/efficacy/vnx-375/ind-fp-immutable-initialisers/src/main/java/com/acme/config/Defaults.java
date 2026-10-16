package com.acme.config;

import com.google.common.collect.ImmutableSet;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Defaults {
    private final List<String> regions = List.of("eu-west-1", "us-east-1");
    private final Map<String, Integer> limits = Collections.emptyMap();
    private final Set<String> reserved = ImmutableSet.of("admin", "root");
    private final String name = "default";
    private final Instant loadedAt = Instant.now();

    public List<String> getRegions() {
        return regions;
    }

    public Map<String, Integer> getLimits() { return limits; }

    public Set<String> getReserved() {
        return reserved;
    }

    public String getName() {
        return name;
    }

    public Instant getLoadedAt() {
        return loadedAt;
    }
}
