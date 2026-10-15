package com.acme.order;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

public class SafeCart {
    private final List<LineItem> items = new ArrayList<>();
    private byte[] secret;
    private Date expires;

    public List<LineItem> getItems() {
        return Collections.unmodifiableList(items);
    }

    public List<LineItem> copyItems() {
        return new ArrayList<>(items);
    }

    public byte[] getSecret() {
        return secret.clone();
    }

    public Date getExpires() {
        return new Date(expires.getTime());
    }

    List<LineItem> internalItems() {
        return items;
    }

    private List<LineItem> raw() {
        return items;
    }
}
