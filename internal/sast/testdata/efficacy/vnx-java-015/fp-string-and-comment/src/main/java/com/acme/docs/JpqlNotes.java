package com.acme.docs;

import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;

public class JpqlNotes {
    private EntityManager em;

    String note(HttpServletRequest request) {
        String name = request.getParameter("name");
        // em.createQuery("from User where name = '" + name + "'") is injectable
        String hint = "do not call em.createQuery(\"... '\" + name + \"'\")";
        log("createQuery refused for " + name);
        return hint;
    }

    void log(String s) {
    }
}
