package com.acme;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.servlet.DefaultServlet;
import org.eclipse.jetty.servlet.ServletHolder;

public class StaticServer {
    public static void main(String[] args) throws Exception {
        Server server = new Server(8080);
        ResourceHandler resources = new ResourceHandler();
~>        resources.setDirectoriesListed(true);
        resources.setResourceBase("./public");
        ServletHolder holder = new ServletHolder("default", DefaultServlet.class);
~>        holder.setInitParameter("dirAllowed", "true");
        server.setHandler(resources);
        server.start();
    }
}
