package com.acme.order;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class SafeOrder {
    private List<LineItem> items;
    private List<LineItem> frozen;
    private byte[] key;
    private Date created;
    private Map<String, String> meta;

    public void setItems(List<LineItem> items) {
        this.items = new ArrayList<>(items);
        this.frozen = List.copyOf(items);
    }

    public SafeOrder(byte[] key, Date created, Map<String, String> meta) {
        this.key = key.clone();
        this.key = Arrays.copyOf(key, key.length);
        this.created = new Date(created.getTime());
        this.meta = Collections.unmodifiableMap(meta);
    }
}
