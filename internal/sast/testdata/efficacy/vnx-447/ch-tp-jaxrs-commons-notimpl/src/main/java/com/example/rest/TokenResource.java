package com.example.rest;

import javax.ws.rs.DELETE;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Response;
import @@sample:o[r]g[.][a]pa[c]he[.]co[m]mo[n]s[.][l]an[g]3[.][N]ot[I]mp[l]em[e]nt[e]dE[x]ce[p]ti[o]n@@;

@Path("/tokens")
public class TokenResource {

    @DELETE
    @Path("{id}")
~>    public Response revokeToken(@PathParam("id") String id)
    {
        throw new NotImplementedException("revocation not wired up");
    }
}
