package com.acme.rs;

import java.net.InetAddress;
import java.util.Map;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Path("/info")
public class InfoResource {

    @GET
    @Path("/props")
    public Response props() {
~>        return Response.ok(System.getProperties()).build();
    }

    @GET
    @Path("/host")
    public Response host() throws Exception {
        String host = InetAddress.getLocalHost().getHostName();
~>        return Response.status(200).entity(host).build();
    }
}
