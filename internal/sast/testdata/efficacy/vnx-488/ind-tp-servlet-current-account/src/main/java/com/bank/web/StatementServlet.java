package com.bank.web;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class StatementServlet extends HttpServlet {
    private String accountId;
    private String requester;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
~>        accountId = req.getParameter("account");
~>        this.requester = req.getRemoteUser();
        resp.setContentType("text/csv");
        resp.getWriter().write(statements.render(accountId, requester));
    }
}
