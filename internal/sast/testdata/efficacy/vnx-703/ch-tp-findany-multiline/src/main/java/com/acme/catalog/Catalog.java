package com.acme.catalog;

import java.util.List;

public class Catalog {

    public Product cheapest(List<Product> products, String sku) {
        return products.stream()
                .filter(p -> p.getSku().equals(sku))
                .findAny()
~>                .get();
    }
}
