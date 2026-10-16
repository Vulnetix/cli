package com.acme;

import javax.annotation.security.PermitAll;
import javax.ws.rs.GET;
import javax.ws.rs.POST;

public class PubResource {
    @GET
    @PermitAll
    public String ping() { return "ok"; }

    @POST
    @PermitAll
    public void register(String body) { }
}
