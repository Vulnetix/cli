package com.acme;

import javax.annotation.security.PermitAll;
import javax.ws.rs.*;

@Path("/management/reports")
public class ManageResource {

~>    @PermitAll
    @GET
    @Path("/management/export")
    public String export() {
        return reports.dump();
    }
}
