package com.acme.auth;

public class LoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        User user = users.find(request.getParameter("user"));
~>        if (user != null && user.getPasswordHash().equals(request.getParameter("hash"))) {
            request.getSession().setAttribute("uid", user.getId());
        }
    }
}
