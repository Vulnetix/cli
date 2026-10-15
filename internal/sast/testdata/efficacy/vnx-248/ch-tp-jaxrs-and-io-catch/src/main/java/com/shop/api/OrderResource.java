package com.shop.api;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;

@Path("/orders")
public class OrderResource {

    @GET
    @Path("/{id}")
    public Order get(@PathParam("id") String id, @QueryParam("rev") String rev) {
~>        long orderId = Long.parseLong(id);
~>        int revision = Integer.valueOf(rev);
        return repo.find(orderId, revision);
    }

    public void export(HttpServletRequest req) {
        try {
~>            int limit = Integer.parseInt(req.getParameter("limit").trim());
            writer.write(repo.export(limit));
        } catch (IOException e) {
            log.warn("export failed", e);
        }
    }
}
