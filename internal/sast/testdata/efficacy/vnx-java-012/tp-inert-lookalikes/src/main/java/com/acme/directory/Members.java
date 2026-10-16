package com.acme.directory;

import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;

public class Members {
    private static final String BASE = "ou=people,dc=acme,dc=com";
    private DirContext ctx;
    private final SearchControls controls = new SearchControls();

    // The same helper shapes with the request value in the way.
    public NamingEnumeration<SearchResult> argumentIsRequestValue(HttpServletRequest request) throws Exception {
        String param = request.getParameter("role");
        Roles roles = RolesFactory.create();
        String role = roles.lookupName(param);
~>        return ctx.search(BASE, "(&(objectClass=person)(employeeType=" + role + "))", controls);
    }

    public NamingEnumeration<SearchResult> receiverBuiltFromRequest(HttpServletRequest request) throws Exception {
        Roles roles = new Roles(request.getParameter("realm"));
        String role = roles.lookupName("staff");
~>        return ctx.search(BASE, "(&(objectClass=person)(employeeType=" + role + "))", controls);
    }

    public NamingEnumeration<SearchResult> receiverFedRequestValue(HttpServletRequest request) throws Exception {
        Roles roles = RolesFactory.create();
        roles.add(request.getParameter("extra"));
        String role = roles.lookupName("staff");
~>        return ctx.search(BASE, "(&(objectClass=person)(employeeType=" + role + "))", controls);
    }

    public NamingEnumeration<SearchResult> helperHandsBackItsArgument(HttpServletRequest request) throws Exception {
        String param = request.getParameter("dept");
        String dept = departmentFor(request, param);
~>        return ctx.search(BASE, "(&(objectClass=person)(ou=" + dept + "))", controls);
    }

    private static String departmentFor(HttpServletRequest request, String param) {
        Departments departments = DepartmentsFactory.create();
        String chosen = departments.byCode(param);
        return chosen;
    }
}
