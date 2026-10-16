package com.acme.rest;

import javax.ws.rs.DELETE;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Response;

@Path("/accounts")
public class AccountResource {
    private final AccountRepository repo;

    public AccountResource(AccountRepository repo) {
        this.repo = repo;
    }

    @DELETE
    @Path("/{id}")
    public Response close(@PathParam("id") long id) {
        try {
            repo.close(id);
            return Response.noContent().build();
        } catch (AccountLockedException e) {
~>            return Response.ok()
                    .entity("{\"error\":\"account locked\"}")
                    .build();
        }
    }
}
