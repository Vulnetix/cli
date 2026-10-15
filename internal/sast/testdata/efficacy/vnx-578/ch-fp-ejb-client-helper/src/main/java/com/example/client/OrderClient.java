package com.example.client;

import javax.ejb.EJB;
import javax.naming.InitialContext;

public class OrderClient {
    @EJB
    private OrderFacade orders;

    public Object lookupRemote(String jndi) throws Exception {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        InitialContext ctx = new InitialContext();
        return cl.loadClass(OrderFacade.class.getName()).cast(ctx.lookup(jndi));
    }
}
