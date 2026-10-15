package com.acme.api;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;

@Path("/reports")
public class ReportResource {

    @GET
    @Path("/raw")
~>    @Deprecated
    public String raw(@QueryParam("q") String q) {
        return dao.rawQuery(q);
    }
}
