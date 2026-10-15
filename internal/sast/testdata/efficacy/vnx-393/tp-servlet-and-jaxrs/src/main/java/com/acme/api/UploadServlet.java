package com.acme.api;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

public class UploadServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try {
            store.save(req.getInputStream());
        } catch (IOException e) {
~>            resp.setStatus(HttpServletResponse.SC_OK);
            resp.getWriter().write("upload failed");
        }
    }

    public Response status(String id) {
        try {
            return Response.ok(store.status(id)).build();
        } catch (IllegalStateException e) {
~>            return Response.ok("error: " + e.getMessage()).build();
        }
    }

    protected void doPut(HttpServletRequest req, HttpServletResponse resp) {
        try {
            store.replace(req.getInputStream());
        } catch (IOException e) {
~>            resp.setStatus(200);
        }
    }
}
