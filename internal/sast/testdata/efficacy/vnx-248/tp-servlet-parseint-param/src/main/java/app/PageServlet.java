package app;

import javax.servlet.http.*;

public class PageServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
~>        int page = Integer.parseInt(request.getParameter("page"));
~>        long id = Long.parseLong( req.getHeader("X-Item-Id") );
~>        UUID token = UUID.fromString(request.getParameter("token"));
        render(response, page, id, token);
    }
}
