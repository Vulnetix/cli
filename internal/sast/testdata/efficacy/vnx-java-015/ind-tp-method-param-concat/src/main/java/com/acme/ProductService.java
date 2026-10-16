package com.acme;

import java.util.List;
import javax.persistence.EntityManager;

public class ProductService {
    private EntityManager em;

    public List<Product> findByCategory(String category) {
~>        return em.createQuery("select p from Product p where p.category = '" + category + "'", Product.class).getResultList();
    }
}
