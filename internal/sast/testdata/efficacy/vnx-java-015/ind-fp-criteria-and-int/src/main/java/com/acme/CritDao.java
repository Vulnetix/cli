package com.acme;

import javax.persistence.EntityManager;
import javax.persistence.criteria.*;
import javax.servlet.http.HttpServletRequest;

public class CritDao {
    private EntityManager em;

    public Object byId(HttpServletRequest request) {
        long id = Long.parseLong(request.getParameter("id"));
        return em.createQuery("select u from User u where u.id = " + id).getResultList();
    }

    public Object crit(String name) {
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<User> q = cb.createQuery(User.class);
        Root<User> r = q.from(User.class);
        q.select(r).where(cb.equal(r.get("name"), name));
        return em.createQuery(q).getResultList();
    }
}
