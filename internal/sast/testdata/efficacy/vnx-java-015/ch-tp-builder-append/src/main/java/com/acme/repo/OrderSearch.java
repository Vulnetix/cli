package com.acme.repo;

import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.servlet.http.HttpServletRequest;

public class OrderSearch {
    private final EntityManager entityManager;

    public OrderSearch(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @SuppressWarnings("unchecked")
    public List<Object> search(HttpServletRequest request) {
        String status = request.getParameter("status");
        StringBuilder jpql = new StringBuilder("select o from Order o where 1=1");
        if (status != null) {
            jpql.append(" and o.status = '").append(status).append("'");
        }
~>        Query q = entityManager.createQuery(jpql.toString());
        return q.getResultList();
    }
}
