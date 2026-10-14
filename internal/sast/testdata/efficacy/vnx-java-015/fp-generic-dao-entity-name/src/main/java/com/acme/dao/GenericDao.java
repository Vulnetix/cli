package com.acme.dao;

import java.util.List;
import javax.persistence.EntityManager;

public abstract class GenericDao<T> {
    private static final String ACTIVE = " where e.active = true";
    protected EntityManager em;
    private final Class<T> type;

    protected GenericDao(Class<T> type) {
        this.type = type;
    }

    public List<T> findAll() {
        return em.createQuery("select e from " + type.getSimpleName() + " e" + ACTIVE, type).getResultList();
    }

    public long count(String entityName) {
        return (Long) em.createQuery("select count(e) from " + entityName + " e").getSingleResult();
    }
}
