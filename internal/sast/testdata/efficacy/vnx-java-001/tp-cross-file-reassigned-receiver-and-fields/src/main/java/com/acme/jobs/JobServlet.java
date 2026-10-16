package com.acme.jobs;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class JobServlet extends HttpServlet {

    // The receiver is rebound at the bottom of the loop: the second pass runs
    // the other class.
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Greeter greeter = new FixedGreeter();
        for (int i = 0; i < 2; i++) {
            String text = greeter.greet(request.getParameter("who"));
~>            Runtime.getRuntime().exec("echo " + text);
            greeter = new EchoGreeter();
        }
    }

    // A public field can be assigned from any class, so its getter is not a constant.
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Settings settings = new Settings();
        settings.name = request.getParameter("name");
        String name = settings.name(request.getParameter("hint"));
~>        Runtime.getRuntime().exec("run " + name);
    }

    // A private field that a setter changes is not a constant either.
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Settings other = new Settings();
        other.mode("x", request.getParameter("mode"));
        String mode = other.mode(request.getParameter("hint"));
~>        Runtime.getRuntime().exec("run " + mode);
    }
}
