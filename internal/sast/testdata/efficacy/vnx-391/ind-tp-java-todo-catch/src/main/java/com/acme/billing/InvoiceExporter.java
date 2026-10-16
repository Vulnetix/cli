package com.acme.billing;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class InvoiceExporter {
    private final Path target;

    public InvoiceExporter(Path target) {
        this.target = target;
    }

    public void export(Invoice invoice) {
        try (BufferedWriter out = Files.newBufferedWriter(target)) {
            out.write(invoice.toCsvLine());
            out.newLine();
~>        } catch (IOException e) {
            // TODO handle this properly
        }
    }
}
