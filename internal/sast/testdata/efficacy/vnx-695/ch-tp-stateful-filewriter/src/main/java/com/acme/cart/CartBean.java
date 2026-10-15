package com.acme.cart;

import java.io.FileWriter;
import java.io.IOException;
import javax.ejb.Stateful;

@Stateful
public class CartBean {

    public void export(String name) throws IOException {
~>        try (FileWriter out = new FileWriter("/var/tmp/" + name)) {
            out.write("cart");
        }
    }
}
