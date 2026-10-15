package com.acme.store;

import java.util.List;

public class ProductRepository {
    public Product find(long id) {
        try {
            return jdbc.queryForObject("select * from product where id = ?", mapper, id);
~>        } catch (Exception e) {
            return null;
        }
    }

    public List<Product> all() {
        try {
            return jdbc.query("select * from product", mapper);
        }
~>        catch (RuntimeException ex)
        {
            cacheMiss++;
            return List.of();
        }
    }
}
