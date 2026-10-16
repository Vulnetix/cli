package com.acme;
import javax.servlet.http.*;
public class PartServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws Exception {
        Part part = req.getPart("doc");
~>        part.write("/srv/app/webapps/ROOT/" + part.getSubmittedFileName());
    }
}
