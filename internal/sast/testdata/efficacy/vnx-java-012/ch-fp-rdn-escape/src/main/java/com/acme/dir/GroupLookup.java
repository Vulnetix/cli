package com.acme.dir;

import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.Rdn;
import javax.servlet.http.HttpServletRequest;

public class GroupLookup {
    private DirContext ctx;

    public Object find(HttpServletRequest req) throws Exception {
        String group = Rdn.escapeValue(req.getParameter("group"));
        return ctx.search("cn=" + group + ",ou=groups,dc=acme,dc=com", "(objectClass=groupOfNames)", new SearchControls());
    }
}
