package com.acme;

import javax.annotation.security.PermitAll;
import javax.ws.rs.DELETE;
import javax.ws.rs.Path;

@Path("/items")
public class ItemResource {
    @DELETE
    @Path("{id}")
~>    @PermitAll
    public void remove(String id) { }
}
