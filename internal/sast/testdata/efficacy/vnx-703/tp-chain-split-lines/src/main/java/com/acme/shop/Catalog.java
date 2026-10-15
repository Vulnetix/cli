package com.acme.shop;

import java.util.List;

public class Catalog {
    public Product cheapest(List<Product> products, String sku) {
        return products.stream()
                .filter(p -> p.sku().equals(sku))
                .findFirst()
~>                .get();
    }
}
