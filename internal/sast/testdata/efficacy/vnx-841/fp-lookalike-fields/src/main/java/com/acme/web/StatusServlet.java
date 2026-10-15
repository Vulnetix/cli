package com.acme.web;

public class StatusServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        response.setStatus(Integer.parseInt(request.getParameter("code")));
        String state = request.getParameter("state");
        if (state != null && state.equals(session.getAttribute("oauthState"))) {
            login(response);
        }
    }
}
