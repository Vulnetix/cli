package com.acme;

public class LdapNotes {
    // ctx.search(base, "(uid=" + request.getParameter("u") + ")", sc) is injectable
    String tip = "ldapTemplate.search(\"ou=x\", \"(cn=\" + request.getParameter(\"cn\") + \")\", mapper)";
}
