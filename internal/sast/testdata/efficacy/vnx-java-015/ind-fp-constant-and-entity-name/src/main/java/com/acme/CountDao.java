package com.acme;

import javax.persistence.EntityManager;

public class CountDao {
    private EntityManager em;

    public long count(Class<?> type) {
        String entity = type.getSimpleName();
        return (Long) em.createQuery("select count(e) from " + entity + " e").getSingleResult();
    }

    public Object all() {
        return em.createQuery("from Account").getResultList();
    }
}
