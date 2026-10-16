package com.acme.cart;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Order {
    private final List<LineItem> lines = new ArrayList<>();
    private Map<String, String> attributes;
    private Set<String> tags;
    private Date placedAt;
    private byte[] signature;

    public List<LineItem> getLines() {
        return Collections.unmodifiableList(lines);
    }

    public Map<String, String> getAttributes() {
        return Map.copyOf(attributes);
    }

    public Set<String> getTags() { return new java.util.HashSet<>(tags); }

    public Date getPlacedAt() {
        return new Date(placedAt.getTime());
    }

    protected byte[] getSignature() {
        return signature.clone();
    }

    public int lineCount() {
        return lines.size();
    }
}
