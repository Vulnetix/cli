package com.acme.shop;

public class OrderServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Order order = orders.find(Long.parseLong(request.getParameter("id")));
~>        order.setStatus(request.getParameter("status"));
        String step = request.getParameter("step");
~>        if ("confirmed".equals(step)) {
            booking.setStatus(BookingStatus.CONFIRMED);
        }
        orders.save(order);
    }
}
