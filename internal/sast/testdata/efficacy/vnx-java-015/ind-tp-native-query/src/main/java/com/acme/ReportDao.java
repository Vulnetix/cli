package com.acme;

import java.util.List;
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;

public class ReportDao {
    private EntityManager entityManager;

    public List<?> search(HttpServletRequest req) {
        String term = req.getParameter("term");
~>        return entityManager.createNativeQuery("SELECT * FROM reports WHERE title LIKE '%" + term + "%'").getResultList();
    }
}
