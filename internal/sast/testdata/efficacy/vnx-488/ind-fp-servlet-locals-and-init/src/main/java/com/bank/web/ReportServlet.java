package com.bank.web;

import java.io.IOException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ReportServlet extends HttpServlet {
    private String reportDir;
    private final String region;
    private int maxRows;

    public ReportServlet() {
        this.region = System.getProperty("region", "eu");
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        reportDir = config.getInitParameter("reportDir");
        maxRows = Integer.parseInt(getServletContext().getInitParameter("maxRows"));
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String account = req.getParameter("account");
        String user = req.getRemoteUser();
        // accountId = req.getParameter("account");  -- removed: shared across requests
        req.setAttribute("account", account);
        req.getSession().setAttribute("lastUser", user);
        resp.getWriter().write(render(reportDir, account, user, maxRows));
    }
}
