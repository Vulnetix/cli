package com.acme.dir;

import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;

public class MailLookup {
    private DirContext ctx;

    public Object find(HttpServletRequest req) throws Exception {
        String mail = req.getParameter("mail");
        Object[] args = new Object[] { mail };
        return ctx.search("ou=people,dc=acme,dc=com", "(mail={0})", args, new SearchControls());
    }
}
