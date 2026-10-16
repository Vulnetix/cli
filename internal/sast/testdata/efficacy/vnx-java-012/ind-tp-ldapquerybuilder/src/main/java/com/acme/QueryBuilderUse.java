package com.acme;

import javax.servlet.http.HttpServletRequest;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.query.LdapQueryBuilder;

public class QueryBuilderUse {
    private LdapTemplate template;

    public Object byRaw(HttpServletRequest request) {
        String raw = request.getParameter("q");
~>        return template.find(LdapQueryBuilder.query().filter("(|(uid=" + raw + ")(mail=" + raw + "))"), Object.class);
    }
}
