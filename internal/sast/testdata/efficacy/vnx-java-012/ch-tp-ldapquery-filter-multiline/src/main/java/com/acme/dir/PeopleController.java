package com.acme.dir;

import static org.springframework.ldap.query.LdapQueryBuilder.query;

import java.util.List;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PeopleController {
    private final LdapTemplate ldap;

    PeopleController(LdapTemplate ldap) { this.ldap = ldap; }

    @GetMapping("/people")
    public List<String> people(@RequestParam("dept") String dept) {
~>        return ldap.search(
                query().base("ou=people")
                        .filter("(departmentNumber=" + dept + ")"),
                (org.springframework.ldap.core.AttributesMapper<String>) a -> (String) a.get("cn").get());
    }
}
