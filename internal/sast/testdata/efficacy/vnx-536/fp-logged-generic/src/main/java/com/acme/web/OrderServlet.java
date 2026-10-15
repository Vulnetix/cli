package com.acme.web;

public class OrderServlet extends HttpServlet {
    private static final Logger log = LoggerFactory.getLogger(OrderServlet.class);

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            process(request);
        } catch (Exception e) {
            log.error("order failed: " + e.getMessage(), e);
            e.printStackTrace();
            response.sendError(500, "Internal error");
            response.getWriter().println("An internal error occurred");
        }
    }
}
