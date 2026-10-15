package app;

import javax.servlet.http.*;
import javax.xml.xpath.*;
import @@sample:o[r]g[.][w]3c[.]do[m][.]D[o]cu[m]en[t]@@;

public class LoginServlet extends HttpServlet {
    private Document users;

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String user = request.getParameter("user");
        String pass = request.getParameter("pass");
~>        String found = XPathFactory.newInstance().newXPath().evaluate("//account[@user='" + user + "' and @pass='" + pass + "']/@id", users);
        response.getWriter().print(found.isEmpty() ? "denied" : "ok");
    }
}
