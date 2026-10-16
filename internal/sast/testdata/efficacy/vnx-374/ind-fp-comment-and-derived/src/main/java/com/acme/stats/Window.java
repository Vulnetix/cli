package com.acme.stats;

import java.util.List;

public class Window {
    private int size;
    private long total;

    // Previously: this.samples = samples; which leaked the caller's list.
    public Window(List<Long> samples) {
        this.size = samples.size();
        this.total = samples.stream().mapToLong(Long::longValue).sum();
    }
}
