package com.acme.ops;

import java.io.IOException;

public class Maintenance {
    // A command text taken from a helper in another class that is handed
    // literals only, on a type name or on a local built from such a call.
    public void listing() throws IOException {
        CommandBook book = CommandBooks.standard();
        String flags = book.entry("listing");
        Runtime.getRuntime().exec("ls " + flags);
    }

    public void staticEntry() throws IOException {
        String flags = Flags.forTool("tar");
        Runtime.getRuntime().exec("tar " + flags);
    }

    public void shellWithInertScript() throws IOException {
        Script script = new Script("nightly", 2);
        String body = script.render("cleanup");
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", "run " + body);
        pb.start();
    }

    // An environment made of constants, and an argument array whose shell
    // script is a constant.
    public void constantEnvironment(String command) throws IOException {
        String locale = "LANG=C";
        String[] env = {locale, "TZ=UTC"};
        Runtime r = Runtime.getRuntime();
        r.exec("/usr/bin/backup", env);
    }

    public void constantScriptInArray() throws IOException {
        String a1 = "";
        String a2 = "";
        if (System.getProperty("os.name").indexOf("Windows") != -1) {
            a1 = "cmd.exe";
            a2 = "/c";
        } else {
            a1 = "sh";
            a2 = "-c";
        }
        String[] args = {a1, a2, "echo " + Greetings.text("hello")};
        ProcessBuilder pb = new ProcessBuilder(args);
        pb.start();
    }
}
