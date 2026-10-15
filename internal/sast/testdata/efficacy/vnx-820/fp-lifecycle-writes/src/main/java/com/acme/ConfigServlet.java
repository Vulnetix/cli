package com.acme;

import javax.annotation.PostConstruct;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServlet;

public class ConfigServlet extends HttpServlet {
    private String root;
    private int limit;
    private String mode;

    public ConfigServlet() {
        limit = 10;
    }

    @Override
    public void init(ServletConfig config) {
        root = config.getInitParameter("root");
    }

    public void setLimit(int limit) {
        this.limit = limit;
    }

    @PostConstruct
    void start() {
        mode = "ready";
    }
}
