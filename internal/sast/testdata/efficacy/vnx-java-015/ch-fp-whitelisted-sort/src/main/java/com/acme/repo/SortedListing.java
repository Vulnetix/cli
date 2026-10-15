package com.acme.repo;

import java.util.List;
import java.util.Set;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;

public class SortedListing {
    private static final Set<String> ALLOWED_SORT = Set.of("name", "price", "createdAt");
    private EntityManager em;

    public List<Product> list(HttpServletRequest request) {
        String sort = request.getParameter("sort");
        if (!ALLOWED_SORT.contains(sort)) {
            sort = "name";
        }
        return em.createQuery("from Product p order by p." + sort, Product.class).getResultList();
    }
}
