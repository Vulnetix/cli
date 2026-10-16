package app;
import javax.servlet.http.*;
public class Ok extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        if (request.isUserInRole("admin")) { show(response); }
        // if ("true".equals(request.getParameter("isAdmin"))) {
        String s = "if (req.query.admin === 'true')";
    }
    void show(HttpServletResponse r) {}
}
