package app;

public class PageServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        int page;
        try {
            page = Integer.parseInt(request.getParameter("page"));
            String raw = request.getParameter("size");
            int size = Integer.parseInt(raw);
        } catch (NumberFormatException e) {
            response.sendError(400);
            return;
        }
    }
}
