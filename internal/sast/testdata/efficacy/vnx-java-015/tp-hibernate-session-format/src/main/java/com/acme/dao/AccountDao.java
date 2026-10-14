package com.acme.dao;

import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;
import org.hibernate.Session;
import org.hibernate.SessionFactory;

public class AccountDao {
    private SessionFactory sessionFactory;

    @GET
    public Object byOwner(@QueryParam("owner") String owner) {
        Session session = sessionFactory.getCurrentSession();
        String hql = String.format("from Account a where a.owner = '%s'", owner);
~>        return session.createQuery(hql).list();
    }
}
