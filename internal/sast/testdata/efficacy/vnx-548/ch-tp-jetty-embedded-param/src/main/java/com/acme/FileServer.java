package com.acme;

import org.eclipse.jetty.servlet.DefaultServlet;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

public class FileServer {
    void configure(ServletContextHandler ctx) {
        ServletHolder holder = new ServletHolder("files", DefaultServlet.class);
        holder.setInitParameter("resourceBase", "/srv/files");
~>        holder.setInitParameter("dirAllowed", "true");
        ctx.addServlet(holder, "/files/*");
    }
}
