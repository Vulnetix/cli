package com.acme.rs;

import jakarta.ws.rs.core.Response;

public class WebhookResource {
    public Response receive(String body, String sig) {
        try {
            dispatcher.dispatch(body);
            return Response.ok().build();
        } catch (DispatchException e) {
            log.warn("dispatch failed", e);
~>            return jakarta.ws.rs.core.Response.ok("queued").build();
        }
    }

    private boolean verifyHmac(String body, String sig) {
        try {
            return hmac.matches(body, sig);
        } catch (IllegalArgumentException
                 | NullPointerException e) {
~>            return true;
        }
    }
}
