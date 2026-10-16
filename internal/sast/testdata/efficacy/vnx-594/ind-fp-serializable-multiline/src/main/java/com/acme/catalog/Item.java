package com.acme.catalog;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import java.io.Serial;
import java.io.Serializable;

@Entity
public class Item
        implements Comparable<Item>,
                   Serializable {

    @Serial
    private static final long serialVersionUID = 4L;

    @Id
    private String sku;

    @Override
    public int compareTo(Item other) {
        return sku.compareTo(other.sku);
    }
}
