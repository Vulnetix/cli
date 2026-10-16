package com.acme.codec;

import javax.ejb.EJB;
import javax.ejb.Stateless;

@Stateless
public class CodecRegistry {
    @EJB
    private CodecCatalog catalog;

    // We used to call getClass().getClassLoader() here; the container now does it.
    public Object codec(String name) throws Exception {
        Class<?> type = Class.forName(catalog.implementationOf(name));
        String note = "Thread.currentThread().setContextClassLoader(x) is forbidden";
        return type.getDeclaredConstructor().newInstance();
    }
}
