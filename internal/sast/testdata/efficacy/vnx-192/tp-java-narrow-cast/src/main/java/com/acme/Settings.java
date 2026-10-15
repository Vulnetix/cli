package com.acme;

import javax.servlet.http.HttpServletRequest;

public class Settings {
    public void apply(HttpServletRequest request) {
        int level = Integer.parseInt(request.getParameter("level"));
~>        byte b = (byte) level;
~>        short port = (short) Integer.parseInt(request.getParameter("port"));
~>        int size = (int) Long.parseLong(request.getParameter("size"));
        configure(b, port, size);
    }
}
