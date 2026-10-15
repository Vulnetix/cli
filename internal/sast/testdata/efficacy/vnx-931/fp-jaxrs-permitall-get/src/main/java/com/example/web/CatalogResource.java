package com.example.web;

import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;

@Path("/catalog")
public class CatalogResource {
    @GET
    @PermitAll
    public String list() { return "[]"; }

    @POST
    @Path("/login")
    @PermitAll
    public String login(String body) { return "ok"; }

    @DELETE
    @RolesAllowed("admin")
    public void clear() { }
}
