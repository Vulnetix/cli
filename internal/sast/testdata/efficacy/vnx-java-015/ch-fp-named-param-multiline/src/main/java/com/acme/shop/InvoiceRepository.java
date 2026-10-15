package com.acme.shop;

import java.util.List;
import javax.persistence.EntityManager;

public class InvoiceRepository {
    private EntityManager em;

    public List<Invoice> forCustomer(String customerId, String status) {
        return em.createQuery(
                "SELECT i FROM Invoice i WHERE i.customer.id = :cid AND i.status = :status",
                Invoice.class)
            .setParameter("cid", customerId)
            .setParameter("status", status)
            .getResultList();
    }
}
