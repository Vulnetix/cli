package com.acme.api;

import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/auth")
public class LegacyAuthResource {

    private final AuthService auth;

    public LegacyAuthResource(AuthService auth) {
        this.auth = auth;
    }

    @POST
    @Path("/basic-login")
~>    @Deprecated
    @Produces(MediaType.APPLICATION_JSON)
    public Response basicLogin(@FormParam("user") String user, @FormParam("pass") String pass) {
        return Response.ok(auth.loginMd5(user, pass)).build();
    }
}
