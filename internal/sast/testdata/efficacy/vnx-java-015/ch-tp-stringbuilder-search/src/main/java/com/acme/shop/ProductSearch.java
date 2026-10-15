package com.acme.shop;

import java.util.List;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;

public class ProductSearch {
    private EntityManager em;

    public List<?> search(HttpServletRequest request) {
        String term = request.getParameter("q");
        StringBuilder jpql = new StringBuilder("SELECT p FROM Product p WHERE 1=1");
        if (term != null) {
            jpql.append(" AND p.name LIKE '%").append(term).append("%'");
        }
~>        return em.createQuery(jpql.toString()).getResultList();
    }
}
