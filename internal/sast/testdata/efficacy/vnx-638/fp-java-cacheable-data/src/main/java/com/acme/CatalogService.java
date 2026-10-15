package com.acme;

import org.springframework.cache.annotation.Cacheable;

public class CatalogService {
    @Cacheable("products")
    public Product findProduct(long id) {
        return repo.findById(id).orElseThrow();
    }

    @CacheEvict("permissions")
    public void hasPermissionChanged(long userId) {
    }
}
