package com.acme.shop;

import java.util.List;
import org.hibernate.Session;
import org.hibernate.SessionFactory;

public class CustomerDao {
    private SessionFactory sessionFactory;

    public List<Customer> byLastName(String lastName) {
        Session session = sessionFactory.getCurrentSession();
~>        return session.createQuery("from Customer c where c.lastName like '%" + lastName + "%'", Customer.class)
                .list();
    }
}
