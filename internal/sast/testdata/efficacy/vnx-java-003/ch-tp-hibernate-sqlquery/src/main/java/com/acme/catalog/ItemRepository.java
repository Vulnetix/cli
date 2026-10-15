package com.acme.catalog;

import java.util.List;
import org.hibernate.Session;

public class ItemRepository {
    private Session session;

    public List<?> search(javax.servlet.http.HttpServletRequest request) {
        String category = request.getParameter("category");
~>        return session.createSQLQuery("select * from item where category = '" + category + "'").list();
    }
}
