package com.acme.ops;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RestoreServlet extends HttpServlet {

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Echo echo = new Echo();
        String job = echo.same(request.getParameter("job"));
~>        Runtime.getRuntime().exec("restore " + job);
~>        Runtime.getRuntime().exec("restore " + echo.same(request.getParameter("job")));
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Holder holder = new Holder(request.getParameter("job"));
        String job = holder.get();
~>        Runtime.getRuntime().exec("restore " + job);
    }

    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Reader reader = new Reader(request);
        String job = reader.fromParameter("job");
~>        Runtime.getRuntime().exec("restore " + job);
        String header = reader.fromHeader();
~>        Runtime.getRuntime().exec("restore " + header);
        String picked = reader.pick(request);
~>        Runtime.getRuntime().exec("restore " + picked);
    }

    protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Mutable box = new Mutable("restore");
        box.set(request.getParameter("job"));
        String job = box.get();
~>        Runtime.getRuntime().exec("restore " + job);
    }

    protected void doOptions(HttpServletRequest request, HttpServletResponse response) throws IOException {
        com.acme.ops.alpha.Names names = new com.acme.ops.alpha.Names();
        String job = names.pick(request.getParameter("job"));
~>        Runtime.getRuntime().exec("restore " + job);
        String unknown = ExternalCatalog.lookup(request.getParameter("job"));
~>        Runtime.getRuntime().exec("restore " + unknown);
    }

    protected void doHead(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Formatter fmt = new Formatter();
        Echo echo = new Echo();
        String twice = fmt.pad(echo.same(request.getParameter("job")));
~>        Runtime.getRuntime().exec("restore " + twice);
        Greeter greeter = lookup();
        String text = greeter.greet(request.getParameter("job"));
~>        Runtime.getRuntime().exec("restore " + text);
    }

    protected void doTrace(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Renderer renderer = new Renderer();
        String chosen = renderer.render("fixed", request.getParameter("job"));
~>        Runtime.getRuntime().exec("restore " + chosen);
    }

    private Greeter lookup() {
        return new FixedGreeter();
    }
}
