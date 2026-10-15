package com.acme.repo;

import java.util.List;
import org.hibernate.Session;
import org.hibernate.SessionFactory;

public class LedgerDao {
    private final SessionFactory sessionFactory;

    public LedgerDao(SessionFactory sf) {
        this.sessionFactory = sf;
    }

    public List<?> entriesFor(String owner) {
        Session session = sessionFactory.getCurrentSession();
~>        return session.createNativeQuery(
                "SELECT * FROM ledger WHERE owner = '" + owner + "' ORDER BY posted_at")
            .list();
    }
}
