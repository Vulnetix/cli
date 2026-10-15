package com.example.web;

import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;

@Path("/accounts")
public class AccountResource {
    @DELETE
    @Path("/{id}")
~>    @PermitAll
    public void delete(@PathParam("id") long id) { }

~>    @PermitAll
    @PUT
    @Path("/{id}/role")
    public void setRole(@PathParam("id") long id, String role) { }

    @RolesAllowed("admin")
    @DELETE
    @Path("/{id}/purge")
    public void purge(@PathParam("id") long id) { }
}
