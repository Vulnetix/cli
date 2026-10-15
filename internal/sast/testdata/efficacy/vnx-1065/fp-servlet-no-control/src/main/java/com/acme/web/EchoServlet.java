package com.acme.web;

import javax.servlet.http.HttpServlet;

public class EchoServlet extends HttpServlet {
    private final ThreadLocal<StringBuilder> buf = ThreadLocal.withInitial(StringBuilder::new);

    void handle() {
        MyThread t = null;
        exitCode(System.exitCodeHolder());
    }

    void exitCode(int c) {}
}
