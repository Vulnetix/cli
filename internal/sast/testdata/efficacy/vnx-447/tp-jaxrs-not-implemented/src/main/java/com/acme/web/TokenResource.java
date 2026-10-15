package com.acme.web;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;
import @@sample:o[r]g[.][a]pa[c]he[.]co[m]mo[n]s[.][l]an[g]3[.][N]ot[I]mp[l]em[e]nt[e]dE[x]ce[p]ti[o]n@@;

@Path("/tokens")
public class TokenResource {

    @POST
    @Path("/revoke")
~>    public Response revoke(String tokenId) {
        throw new NotImplementedException("revocation");
    }
}
