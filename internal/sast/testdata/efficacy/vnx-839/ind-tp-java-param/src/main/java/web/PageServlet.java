package web;

public class PageServlet extends HttpServlet {
    private final List<String> pages = loadPages();

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        int n = Integer.parseInt(request.getParameter("page"));
~>        if (n >= pages.size()) {
            response.sendError(404);
            return;
        }
        response.getWriter().write(pages.get(n));
    }
}
