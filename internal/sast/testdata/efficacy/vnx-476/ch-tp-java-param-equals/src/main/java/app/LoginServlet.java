package app;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoginServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        String mode = request.getParameter("mode");
        String user = request.getParameter("user");
~>        if (mode.equals("admin")) {
            response.setStatus(403);
        }
~>        int length = System.getenv("APP_SALT").length();
    }
}
