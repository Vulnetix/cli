package com.acme.catalog;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import java.util.ArrayList;
import java.util.List;

@Entity
public class Product {
    @Id
    private Long id;

    @OneToMany(mappedBy = "product")
    private List<Variant> variants = new ArrayList<>();

    public List<Variant> getVariants() {
        return variants;
    }
}
