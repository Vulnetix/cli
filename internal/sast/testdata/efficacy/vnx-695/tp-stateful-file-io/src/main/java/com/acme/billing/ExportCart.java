package com.acme.billing;

import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import javax.ejb.Stateful;

@Stateful
public class ExportCart {

    public void save(byte[] data) throws IOException {
~>        try (FileOutputStream out = new FileOutputStream("/var/exports/cart.bin")) {
            out.write(data);
        }
    }

    public int peek(String name) throws IOException {
~>        FileReader r = new FileReader(name);
        return r.read();
    }
}
