package com.acme.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UploadServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try {
            Uploads.store(req.getInputStream());
            resp.setStatus(HttpServletResponse.SC_CREATED);
        } catch (StorageFullException e) {
~>            resp.setStatus(HttpServletResponse.SC_OK);
            resp.getWriter().write("upload failed");
        }
    }
}
