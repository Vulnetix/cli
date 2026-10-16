package com.acme;

import javax.servlet.http.HttpServletRequest;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;

public class ObjFilters {
    private LdapTemplate ldapTemplate;

    public Object find(HttpServletRequest request) {
        AndFilter f = new AndFilter();
        f.and(new EqualsFilter("objectclass", "person"));
        f.and(new EqualsFilter("uid", request.getParameter("uid")));
        return ldapTemplate.search("ou=people", f.encode(), (org.springframework.ldap.core.AttributesMapper<Object>) a -> a);
    }
}
