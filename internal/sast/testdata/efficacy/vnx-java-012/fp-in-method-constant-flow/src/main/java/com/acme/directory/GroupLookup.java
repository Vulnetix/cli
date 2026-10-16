package com.acme.directory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;

public class GroupLookup {
    private static final String BASE = "ou=groups,dc=acme,dc=com";
    private DirContext ctx;
    private final SearchControls controls = new SearchControls();

    // 2 * 3 >= 6 holds, so the filter never uses the request value.
    public NamingEnumeration<SearchResult> admins(HttpServletRequest request) throws Exception {
        String group = request.getParameter("group");
        int tier = 3;
        String cn;
        if (2 * tier >= 6) cn = "administrators";
        else cn = group;
        String filter = "(&(objectClass=groupOfNames)(cn=" + cn + "))";
        return ctx.search(BASE, filter, controls);
    }

    public NamingEnumeration<SearchResult> members(HttpServletRequest request) throws Exception {
        String dept = request.getParameter("dept");
        int schemaVersion = 2;
        String attr = schemaVersion != 2 ? dept : "memberOf";
        return ctx.search(BASE, "(" + attr + "=*)", controls);
    }

    public NamingEnumeration<SearchResult> byType(HttpServletRequest request) throws Exception {
        String type = request.getParameter("type");
        String kind = "posix";
        String objectClass;
        switch (kind) {
            case "posix":
                objectClass = "posixGroup";
                break;
            default:
                objectClass = type;
                break;
        }
        return ctx.search(BASE, "(objectClass=" + objectClass + ")", controls);
    }

    public NamingEnumeration<SearchResult> picked(HttpServletRequest request) throws Exception {
        List<String> names = new ArrayList<String>();
        names.add(request.getParameter("name"));
        names.add("staff");
        names.remove(0);
        String name = names.get(0);
        Map<String, String> attrs = new HashMap<String, String>();
        attrs.put("lookup", "uid");
        attrs.put("user", request.getHeader("X-User"));
        String key = attrs.get("lookup");
        return ctx.search(BASE, "(&(cn=" + name + ")(" + key + "=*))", controls);
    }

    public NamingEnumeration<SearchResult> owners(HttpServletRequest request) throws Exception {
        String scope = request.getParameter("scope");
        String filter = ownerFilter(scope);
        return ctx.search(BASE, filter, controls);
    }

    private String ownerFilter(String scope) {
        return "(&(objectClass=groupOfNames)(owner=*))";
    }
}
