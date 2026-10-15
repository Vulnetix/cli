package com.acme.shop;

import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
public class Invoice implements Comparable<Invoice>, java.io.Serializable {
    private static final long serialVersionUID = 1L;
    @Id
    private Long id;

    public int compareTo(Invoice o) {
        return id.compareTo(o.id);
    }
}
