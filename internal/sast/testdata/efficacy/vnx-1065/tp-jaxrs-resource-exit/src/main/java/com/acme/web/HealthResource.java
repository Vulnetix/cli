package com.acme.web;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

@Path("/health")
public class HealthResource {
    @GET
    public String check() {
        if (broken()) {
~>            System .exit( 3 );
        }
        return "ok";
    }

    private boolean broken() { return false; }
}
