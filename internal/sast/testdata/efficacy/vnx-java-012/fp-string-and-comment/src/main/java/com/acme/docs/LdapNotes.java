package com.acme.docs;

import javax.naming.directory.DirContext;
import javax.servlet.http.HttpServletRequest;

public class LdapNotes {
    String note(HttpServletRequest request) {
        String user = request.getParameter("user");
        // ctx.search(base, "(uid=" + user + ")", sc) is injectable
        String hint = "never ctx.search(base, filter + user)";
        log("ldap search rejected for " + user);
        return hint;
    }

    void log(String s) {
    }
}
