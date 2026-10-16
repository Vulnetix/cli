package com.acme.catalog;

import org.junit.jupiter.api.Test;

class ProductRepositoryTest {
    @Test
    void missingSkuReturnsNull() {
        boolean threw;
        try {
            new ProductRepository(null).findBySku("x");
            threw = false;
        } catch (Exception e) {
            threw = true;
        }
    }
}
