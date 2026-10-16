package com.acme.cache;

import java.util.HashMap;
import java.util.List;

class Segment {
    private HashMap<String, Object> entries;
    private List<String> order;

    Segment(HashMap<String, Object> entries) {
        this.entries = entries;
    }

    private void adoptOrder(List<String> order) {
        this.order = order;
    }

    void reset(HashMap<String, Object> fresh) {
        entries = fresh;
    }
}
