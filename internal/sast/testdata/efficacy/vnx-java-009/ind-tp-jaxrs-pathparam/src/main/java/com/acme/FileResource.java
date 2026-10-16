package com.acme;

import java.io.*;
import javax.ws.rs.*;

@Path("/files")
public class FileResource {
    @GET
    @Path("/{name}")
    public InputStream get(@PathParam("name") String name) throws IOException {
~>        return new FileInputStream("/data/store/" + name);
    }
}
