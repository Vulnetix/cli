package com.acme;

import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;

public class PosNative {
    private EntityManager em;

    public Object find(HttpServletRequest request) {
        return em.createNativeQuery("SELECT * FROM t WHERE c = ?1").setParameter(1, request.getParameter("c")).getResultList();
    }
}
