package com.acme.repo;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;

public class ProductSearch {
    Predicate byName(CriteriaBuilder cb, Root<Product> root, String q) {
~>        return cb.like(root.get("name"), "%" + q + "%");
    }

    Predicate bySku(CriteriaBuilder cb, Root<Product> root, String sku) {
~>        return cb.equal(cb.lower(root.get("sku")), sku.toLowerCase());
    }

    Predicate byPrefix(CriteriaBuilder cb, Root<Product> root, String p) {
        return cb.like(root.get("name"), p + "%");
    }
}
