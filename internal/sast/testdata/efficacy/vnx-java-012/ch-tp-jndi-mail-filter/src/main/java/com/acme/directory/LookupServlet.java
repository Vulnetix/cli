package com.acme.directory;

import java.io.IOException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LookupServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String email = request.getParameter("email");
        String filter = "(&(objectClass=person)(mail=" + email + "))";
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        try {
            DirContext ctx = new InitialDirContext();
~>            NamingEnumeration<SearchResult> res = ctx.search("ou=people,dc=acme,dc=com", filter, controls);
            response.getWriter().print(res.hasMore());
        } catch (NamingException e) {
            response.sendError(500);
        }
    }
}
