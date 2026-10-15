package com.acme.billing;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class InvoiceImport {
    public List<Invoice> read(String path) throws IOException {
        List<Invoice> out = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader("invoices.csv"))) {
            String line;
            while ((line = reader.readLine()) != null) {
~>                String[] cols = line.split("\\s*,\\s*");
                out.add(new Invoice(cols[0], cols[1], cols[2]));
            }
        }
        return out;
    }
}
