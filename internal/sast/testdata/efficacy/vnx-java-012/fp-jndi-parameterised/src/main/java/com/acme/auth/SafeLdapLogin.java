package com.acme.auth;

import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;

public class SafeLdapLogin {
    private DirContext ctx;

    boolean login(HttpServletRequest request) throws Exception {
        String user = request.getParameter("user");
        SearchControls sc = new SearchControls();
        Object a = ctx.search("ou=people,dc=acme,dc=com", "(uid={0})", new Object[] {user}, sc);
        Object[] args = {user};
        Object b = ctx.search("ou=people,dc=acme,dc=com", "(&(uid={0})(objectClass=person))", args, sc);
        return a != null && b != null;
    }
}
