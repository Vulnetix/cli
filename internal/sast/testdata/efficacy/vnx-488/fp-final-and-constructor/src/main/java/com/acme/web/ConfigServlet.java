package com.acme.web;

public class ConfigServlet extends HttpServlet {
    private String banner;
    private int hits;

    @Override
    public void init(ServletConfig config) {
        banner = config.getInitParameter("banner");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        hits = hits + 1;
        response.getWriter().println(banner);
    }
}
