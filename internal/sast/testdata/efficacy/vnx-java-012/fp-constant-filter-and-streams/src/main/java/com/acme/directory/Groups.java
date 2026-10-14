package com.acme.directory;

import java.util.List;
import java.util.stream.Collectors;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;

public class Groups {
    private DirContext ctx;
    private static final String ADMINS = "(memberOf=cn=admins,ou=groups,dc=acme,dc=com)";

    List<String> admins(HttpServletRequest request, List<String> names) throws Exception {
        String q = request.getParameter("q");
        ctx.search("ou=people,dc=acme,dc=com", ADMINS, new SearchControls());
        return names.stream().filter(n -> n.contains(q)).collect(Collectors.toList());
    }

    List<String> search(HttpServletRequest request, java.util.List<String> all) {
        String term = request.getParameter("term");
        return all.stream().filter(s -> s.startsWith(term)).collect(Collectors.toList());
    }
}
