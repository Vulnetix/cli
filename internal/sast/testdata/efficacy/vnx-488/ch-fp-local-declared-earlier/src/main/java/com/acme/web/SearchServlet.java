package com.acme.web;

public class SearchServlet extends HttpServlet {
    private final Index index = new Index();

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String term;
        String[] tags;
        term = req.getParameter("q");
        tags = req.getParameterValues("tag");
        var page = req.getParameter("page");
        resp.getWriter().print(index.search(term, tags, page));
    }
}
