package com.acme.directory;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;

public class EscapedLookup {
    public boolean exists(DirContext ctx, HttpServletRequest request) throws NamingException {
        String user = escapeLdapSearchFilter(request.getParameter("user"));
        NamingEnumeration<SearchResult> res = ctx.search("dc=acme,dc=com", "(uid=" + user + ")", new SearchControls());
        return res.hasMore();
    }

    static String escapeLdapSearchFilter(String in) {
        StringBuilder sb = new StringBuilder();
        for (char c : in.toCharArray()) {
            switch (c) {
                case '\\': sb.append("\\5c"); break;
                case '*': sb.append("\\2a"); break;
                case '(': sb.append("\\28"); break;
                case ')': sb.append("\\29"); break;
                case '\0': sb.append("\\00"); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }
}
