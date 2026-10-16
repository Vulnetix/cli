package web;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.*;

public class ItemServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
~>        int id = Integer.parseInt(request.getParameter("id"));
        response.getWriter().println(id);
    }
}
