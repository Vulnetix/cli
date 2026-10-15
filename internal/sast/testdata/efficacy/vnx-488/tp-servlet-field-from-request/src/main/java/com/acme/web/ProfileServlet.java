package com.acme.web;

import javax.servlet.http.HttpServlet;

@WebServlet("/profile")
public class ProfileServlet extends HttpServlet {
    private String userName;
    private String accountId;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
~>        userName = request.getParameter("user");
~>        this.accountId = request.getHeader("X-Account");
        response.getWriter().println(render(userName, accountId));
    }
}
