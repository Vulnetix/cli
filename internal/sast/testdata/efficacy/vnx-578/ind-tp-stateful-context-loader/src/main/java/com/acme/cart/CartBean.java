package com.acme.cart;

import jakarta.ejb.Stateful;
import java.io.InputStream;

@Stateful
public class CartBean {
    private ClassLoader rulesLoader;

    public InputStream rules() {
~>        ClassLoader previous = Thread.currentThread().getContextClassLoader();
        try {
~>            Thread.currentThread().setContextClassLoader(rulesLoader);
            return evaluate();
        } finally {
~>            Thread.currentThread().setContextClassLoader(previous);
        }
    }

    private InputStream evaluate() { return null; }
}
