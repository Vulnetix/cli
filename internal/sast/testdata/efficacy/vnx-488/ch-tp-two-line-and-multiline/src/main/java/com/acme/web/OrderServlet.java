package com.acme.web;

public class OrderServlet extends HttpServlet {
    private String orderId;
    private Cookie[] cookies;

    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String id = request.getParameter("order");
        validateFormat(id);
~>        orderId = id;
~>        this.cookies = request.getCookies();
        response.setStatus(200);
    }
}
