package com.acme.repo;

import java.util.List;
import javax.persistence.EntityManager;

public abstract class BaseDao<T> {
    private static final String ACTIVE = " e where e.active = true";
    protected EntityManager em;
    private final Class<T> type;

    protected BaseDao(Class<T> type) {
        this.type = type;
    }

    public List<T> findActive() {
        return em.createQuery("select e from " + type.getName() + ACTIVE, type).getResultList();
    }

    public long count() {
        return em.createQuery("select count(e) from " + Employee.class.getSimpleName() + " e", Long.class).getSingleResult();
    }
}
