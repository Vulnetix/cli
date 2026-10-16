package com.acme;

import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.servlet.ServletHolder;

final class Web {
    static void configure(ResourceHandler resources, ServletHolder holder) {
        resources.setDirectoriesListed(false);
        holder.setInitParameter("dirAllowed", "false");
    }
}
