package com.acme.ops;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BackupServlet extends HttpServlet {

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        ConfigReader cfg = new ConfigReader();
        String tool = cfg.toolName();
        Runtime.getRuntime().exec("echo " + tool);
        Runtime.getRuntime().exec("echo " + cfg.profileName());
        Runtime.getRuntime().exec("echo " + cfg.describe());
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String dir = ConfigReader.defaultDir();
        Runtime.getRuntime().exec("ls " + dir);
        Runtime.getRuntime().exec("ls " + ConfigReader.defaultDir());
    }

    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Sanitizer sanitizer = new Sanitizer();
        String arg = sanitizer.clean(request.getParameter("path"));
        Runtime.getRuntime().exec("ls " + arg);
        String label = sanitizer.labelFor(request.getParameter("who"), "weekly");
        Runtime.getRuntime().exec("echo " + label);
    }

    protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        ConfigReader cfg = new ConfigReader();
        Formatter fmt = new Formatter();
        String label = fmt.pad(cfg.profileName());
        Runtime.getRuntime().exec("echo " + label);
        String twice = fmt.pad(fmt.pad(cfg.toolName()));
        Runtime.getRuntime().exec("echo " + twice);
    }

    protected void doOptions(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Holder holder = new Holder("uname");
        String cmd = holder.get();
        Runtime.getRuntime().exec("echo " + cmd);
        Runtime.getRuntime().exec("echo " + new Holder("date").get());
    }

    protected void doHead(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Greeter greeter = new FixedGreeter();
        String text = greeter.greet(request.getParameter("who"));
        Runtime.getRuntime().exec("echo " + text);
        Greeter other = lookup();
        String fixed = other.greet("friend");
        Runtime.getRuntime().exec("echo " + fixed);
    }

    protected void doTrace(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Renderer renderer = new Renderer();
        String page = renderer.render(request.getParameter("title"));
        Runtime.getRuntime().exec("echo " + page);
        String chosen = renderer.render(request.getParameter("title"), "fixed");
        Runtime.getRuntime().exec("echo " + chosen);
    }

    private Greeter lookup() {
        return new FixedGreeter();
    }
}
