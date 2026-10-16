package com.acme.billing;

import java.io.IOException;

public class InvoiceService {
    private final Ledger ledger;

    public InvoiceService(Ledger ledger) {
        this.ledger = ledger;
    }

    public void post(Invoice invoice) {
        try {
            ledger.write(invoice);
        } catch (Exception e) {}
    }

    public void archive(Invoice invoice) {
        try {
            ledger.archive(invoice.id());
        } catch(IOException ex){ }
    }

    public void close() {
        try { ledger.flush(); }
        catch (final RuntimeException | IOException e) { }
    }
}
