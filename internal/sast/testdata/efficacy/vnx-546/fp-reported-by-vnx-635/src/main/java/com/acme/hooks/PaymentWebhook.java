package com.acme.hooks;

public class PaymentWebhook {
    public void handle(String body, String signatureHeader) {
        // TODO(jdoe): verify the webhook signature before trusting the payload
        Event event = Event.parse(body);
        ledger.apply(event);
    }
}
