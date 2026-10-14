package com.acme.web;

import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SearchServlet extends javax.servlet.http.HttpServlet {
    private EntityManager entityManager;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String term = request.getParameter("q");
        String sql = "SELECT * FROM products WHERE name LIKE '%" + term + "%'";
~>        Object rows = entityManager.createNativeQuery(sql).getResultList();
~>        Object more = entityManager.createNativeQuery(
                "SELECT * FROM tags WHERE label = '" + request.getParameter("tag") + "'")
            .getResultList();
    }
}
