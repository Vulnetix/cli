package com.acme.dir;

import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;

public class UserLookup {
    private DirContext ctx;

    public NamingEnumeration<SearchResult> find(HttpServletRequest req) throws Exception {
        String user = req.getParameter("user");
        StringBuilder f = new StringBuilder("(&(objectClass=person)(uid=").append(user).append("))");
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
~>        return ctx.search("ou=people,dc=acme,dc=com", f.toString(), sc);
    }
}
