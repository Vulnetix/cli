package com.acme.web;

public class SafeServlet extends HttpServlet {
    private final UserService users;
    private static final Logger log = LoggerFactory.getLogger(SafeServlet.class);

    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String userName = request.getParameter("user");
        String accountId;
        accountId = request.getHeader("X-Account");
        request.setAttribute("user", userName);
        response.getWriter().println(users.render(userName, accountId));
    }
}
