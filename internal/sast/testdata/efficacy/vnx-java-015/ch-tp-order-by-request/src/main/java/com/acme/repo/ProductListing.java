package com.acme.repo;

import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import javax.servlet.http.HttpServletRequest;

public class ProductListing {
    private EntityManager em;

    public List<Product> list(HttpServletRequest request) {
        String sort = request.getParameter("sort");
~>        TypedQuery<Product> q = em.createQuery("from Product p order by p." + sort, Product.class);
        return q.getResultList();
    }
}
