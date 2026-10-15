package com.example.cart;

import java.io.InputStream;
import javax.ejb.Stateful;

@Stateful
public class CartBean {
    public InputStream rules(ClassLoader custom) {
~>        ClassLoader previous = Thread.currentThread().getContextClassLoader();
~>        Thread.currentThread().setContextClassLoader(custom);
        try {
~>            return getClass().getClassLoader().getResourceAsStream("cart-rules.xml");
        } finally {
            Thread.currentThread()
~>                    .setContextClassLoader(previous);
        }
    }
}
