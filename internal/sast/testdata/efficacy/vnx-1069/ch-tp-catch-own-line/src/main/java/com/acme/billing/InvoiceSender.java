package com.acme.billing;

public class InvoiceSender {
    private final Mailer mailer;

    public InvoiceSender(Mailer mailer) {
        this.mailer = mailer;
    }

    public void send(Invoice invoice) {
        try {
            mailer.deliver(invoice.toMessage());
        }
~>        catch (final MailException | IllegalStateException failure)
        {
        }
    }
}
