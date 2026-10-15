package com.acme.orders;

import org.hibernate.Session;
import org.hibernate.SessionFactory;

public class OrderService {
    private final SessionFactory factory;

    public OrderService(SessionFactory factory) {
        this.factory = factory;
    }

~>    public void checkout(long cartId, long userId) {
        Session session = factory.openSession();
        Cart cart = session.get(Cart.class, cartId);
        User user = session.get(User.class, userId);
        Order order = new Order(cart, user);
        session.save(order);
        session.update(user);
        session.delete(cart);
        session.close();
    }
}
