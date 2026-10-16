package com.acme.billing;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class InvoiceImporter {

    public List<Invoice> importInvoices(Path dir) throws IOException {
        List<Invoice> invoices = new ArrayList<>();
        try (BufferedReader reader = Files.newBufferedReader(dir.resolve("invoices.csv"))) {
            String line = reader.readLine();
            while ((line = reader.readLine()) != null) {
~>                String[] cols = line.split("\\s*,\\s*");
                invoices.add(new Invoice(cols[0], cols[1], Long.parseLong(cols[2])));
            }
        }
        return invoices;
    }
}
