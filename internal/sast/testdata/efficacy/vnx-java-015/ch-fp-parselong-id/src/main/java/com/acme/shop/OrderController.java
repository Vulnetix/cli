package com.acme.shop;

import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;

public class OrderController {
    private EntityManager em;

    public Object order(HttpServletRequest request) {
        long id = Long.parseLong(request.getParameter("id"));
        return em.createQuery("SELECT o FROM Order o WHERE o.id = " + id).getSingleResult();
    }
}
