package com.acme.repo;

import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.servlet.http.HttpServletRequest;

public class ReportRepository {
    private static final String TOTALS = "select sum(o.total) from Order o";
    private EntityManager em;

    public Object totals(HttpServletRequest request) {
        String region = request.getParameter("region");
        Object t = em.createQuery(TOTALS).getSingleResult();
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<Order> cq = cb.createQuery(Order.class);
        cq.where(cb.equal(cq.from(Order.class).get("region"), region));
        List<Order> orders = em.createQuery(cq).getResultList();
        int limit = Integer.parseInt(request.getParameter("limit"));
        return em.createQuery("select o from Order o order by o.id desc limit " + limit).getResultList();
    }
}
