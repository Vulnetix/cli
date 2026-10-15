package com.acme.cli;

import java.io.IOException;
import javax.servlet.http.HttpServletResponse;

public class Main {
    public static void main(String[] args) {
        System.out.println("acme-cli on Java " + System.getProperty("java.version"));
    }

    void mode(HttpServletResponse response) throws IOException {
        String mode = System.getProperty("acme.mode", "standard");
        response.getWriter().println("mode=" + mode);
    }
}
