package com.acme.docs;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

@Path("/documents")
public class DocumentResource {
    private static final String STORE = "/srv/documents";

    @GET
    public Response download(@QueryParam("name") String name) throws Exception {
~>        InputStream in = new FileInputStream(STORE + File.separator + name);
        return Response.ok(in).build();
    }
}
