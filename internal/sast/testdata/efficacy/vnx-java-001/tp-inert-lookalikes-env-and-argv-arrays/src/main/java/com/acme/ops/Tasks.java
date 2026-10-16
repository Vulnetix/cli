package com.acme.ops;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public class Tasks {
    // Helper shapes that look inert but are handed or built from request data.
    public void helperReceivesRequestValue(HttpServletRequest request) throws IOException {
        String param = request.getParameter("tool");
        CommandBook book = CommandBooks.standard();
        String flags = book.entry(param);
~>        Runtime.getRuntime().exec("ls " + flags);
    }

    public void receiverBuiltFromRequest(HttpServletRequest request) throws IOException {
        CommandBook book = new CommandBook(request.getParameter("book"));
        String flags = book.entry("listing");
~>        Runtime.getRuntime().exec("ls " + flags);
    }

    public void sourceLikeName() throws IOException {
        String flags = Console2.readLine("flags");
~>        Runtime.getRuntime().exec("ls " + flags);
    }

    // A request value in the environment of the child.
    public void environmentFromRequest(HttpServletRequest request) throws IOException {
        String value = request.getParameter("home");
        String[] env = {"HOME=" + value};
        Runtime r = Runtime.getRuntime();
~>        r.exec("/usr/bin/backup", env);
    }

    public void inlineEnvironment(HttpServletRequest request) throws IOException {
        String path = request.getHeader("X-Path");
~>        Runtime.getRuntime().exec("/usr/bin/backup", new String[] {"PATH=" + path});
    }

    public void environmentThroughHelper(HttpServletRequest request, java.io.File dir) throws IOException {
        String raw = request.getParameter("opt");
        Option option = OptionFactory.create();
        String opt = option.normalise(raw);
        String[] env = {opt};
~>        Runtime.getRuntime().exec("/usr/bin/backup", env, dir);
    }

    // A shell started through an argument array held in a local.
    public void shellArrayInLocals(HttpServletRequest request) throws IOException {
        String bar = request.getParameter("msg");
        String a1 = "";
        String a2 = "";
        if (System.getProperty("os.name").indexOf("Windows") != -1) {
            a1 = "cmd.exe";
            a2 = "/c";
        } else {
            a1 = "sh";
            a2 = "-c";
        }
        String[] args = {a1, a2, "echo " + bar};
~>        ProcessBuilder pb = new ProcessBuilder(args);
        pb.start();
    }

    public void shellArrayBranches(HttpServletRequest request) throws IOException {
        String bar = request.getParameter("msg");
        String cmd = Commands.base("echo");
        String[] args = null;
        if (System.getProperty("os.name").indexOf("Windows") != -1) {
            String a1 = "cmd.exe";
            String a2 = "/c";
            args = new String[] {a1, a2, cmd, bar};
        } else {
            String a1 = "sh";
            String a2 = "-c";
            args = new String[] {a1, a2, cmd + bar};
        }
        Runtime r = Runtime.getRuntime();
~>        r.exec(args);
    }
}
