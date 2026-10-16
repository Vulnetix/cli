package com.acme.directory;

import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;

public class Roster {
    private static final String BASE = "ou=people,dc=acme,dc=com";
    private DirContext ctx;
    private final SearchControls controls = new SearchControls();

    // The request value goes into a helper that ignores it; what comes back is
    // a constant from a call into another class with literal arguments.
    public NamingEnumeration<SearchResult> forDepartment(HttpServletRequest request) throws Exception {
        String param = request.getParameter("dept");
        String dept = fixedDepartment(request, param);
        return ctx.search(BASE, "(&(objectClass=person)(ou=" + dept + "))", controls);
    }

    public NamingEnumeration<SearchResult> forRole(HttpServletRequest request) throws Exception {
        String param = request.getParameter("role");
        Roles roles = RolesFactory.create();
        String role = roles.lookupName("staff");
        return ctx.search(BASE, "(&(objectClass=person)(employeeType=" + role + "))", controls);
    }

    private static String fixedDepartment(HttpServletRequest request, String param) {
        String seen = param.trim();
        Departments departments = DepartmentsFactory.create();
        String chosen = departments.byCode("ENG");
        return chosen;
    }
}
