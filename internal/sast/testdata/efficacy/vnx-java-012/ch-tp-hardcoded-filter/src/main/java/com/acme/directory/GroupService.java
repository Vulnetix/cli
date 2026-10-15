package com.acme.directory;

import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.filter.HardcodedFilter;

public class GroupService {
    private final LdapTemplate ldapTemplate;

    public GroupService(LdapTemplate t) {
        this.ldapTemplate = t;
    }

    public List<String> members(HttpServletRequest request) {
        String dept = request.getParameter("dept");
        AndFilter filter = new AndFilter();
        filter.and(new EqualsFilter("objectclass", "person"));
~>        filter.and(new HardcodedFilter("(department=" + dept + ")"));
        AttributesMapper<String> m = a -> (String) a.get("cn").get();
        return ldapTemplate.search("ou=people", filter.encode(), m);
    }
}
