import javax.servlet.http.*;
import java.net.*;

public class Loader extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse resp) throws Exception {
        String lib = request.getParameter("lib");
        System.load(lib);
        Runtime.getRuntime().load(request.getParameter("other"));
        URLClassLoader cl = new URLClassLoader(new URL[] {new URL(request.getParameter("u"))});
        Class.forName(request.getParameter("c"));
    }
}
