package com.acme;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

public class TransferBean {
    @PersistenceContext
    private EntityManager em;

~>    public synchronized void transfer(long from, long to, long cents) {
        Account a = em.find(Account.class, from);
        Account b = em.find(Account.class, to);
        Long limit = em.createQuery("select l.cents from Limit l where l.account = :a", Long.class)
            .setParameter("a", a).getSingleResult();
        a.debit(cents);
        b.credit(cents);
        em.merge(a);
        em.merge(b);
        em.persist(new AuditEntry(from, to, cents));
    }
}
