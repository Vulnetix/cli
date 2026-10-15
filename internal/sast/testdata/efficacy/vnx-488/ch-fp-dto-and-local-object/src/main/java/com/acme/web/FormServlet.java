package com.acme.web;

public class FormServlet extends HttpServlet {
    private static final Logger log = LoggerFactory.getLogger(FormServlet.class);

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        Form form = new Form();
        form.user = req.getParameter("user");
        form.email = req.getParameter("email");
        log.info("user {}", req.getParameter("user"));
        save(form);
    }
}
