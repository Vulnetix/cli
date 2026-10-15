package com.acme.directory;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.servlet.http.HttpServletRequest;

public class AdAuthenticator {
    private static final String BASE = "dc=corp,dc=acme,dc=com";

    public boolean exists(HttpServletRequest req, LdapContext ldap) throws NamingException {
        String username = req.getParameter("username");
        String f = String.format("(&(objectCategory=user)(sAMAccountName=%s))", username);
        NamingEnumeration<SearchResult> answer =
~>            ldap.search(BASE,
                f,
                new SearchControls());
        return answer.hasMoreElements();
    }
}
