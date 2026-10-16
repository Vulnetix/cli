package com.acme;

import java.io.IOException;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.servlet.http.*;

public class LdapLogin extends HttpServlet {
    private DirContext ctx;

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String user = request.getParameter("username");
        String filter = "(&(objectClass=person)(uid=" + user + "))";
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        try {
~>            NamingEnumeration<SearchResult> res = ctx.search("ou=people,dc=acme,dc=com", filter, sc);
            response.getWriter().print(res.hasMore());
        } catch (NamingException e) {
            response.sendError(500);
        }
    }
}
