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

public class PeopleLookup {
    private static final String BASE = "ou=people,dc=acme,dc=com";
    private DirContext ctx;
    private final SearchControls controls = new SearchControls();

    // 2 * 2 >= 6 is false: the request value is the one searched for.
    public NamingEnumeration<SearchResult> byName(HttpServletRequest request) throws Exception {
        String user = request.getParameter("user");
        int tier = 2;
        String cn;
        if (2 * tier >= 6) cn = "administrators";
        else cn = user;
        String filter = "(&(objectClass=person)(cn=" + cn + "))";
~>        return ctx.search(BASE, filter, controls);
    }

    public NamingEnumeration<SearchResult> byAttr(HttpServletRequest request) throws Exception {
        String attr = request.getParameter("attr");
        int schemaVersion = 1;
        String name = schemaVersion != 2 ? attr : "mail";
~>        return ctx.search(BASE, "(" + name + "=*)", controls);
    }

    public NamingEnumeration<SearchResult> byType(HttpServletRequest request) throws Exception {
        String type = request.getParameter("type");
        String kind = "custom";
        String objectClass;
        switch (kind) {
            case "posix":
                objectClass = "posixAccount";
                break;
            default:
                objectClass = type;
                break;
        }
~>        return ctx.search(BASE, "(objectClass=" + objectClass + ")", controls);
    }

    public NamingEnumeration<SearchResult> picked(HttpServletRequest request) throws Exception {
        List<String> names = new ArrayList<String>();
        names.add("staff");
        names.add(request.getParameter("name"));
        names.remove(0);
        String name = names.get(0);
~>        return ctx.search(BASE, "(cn=" + name + ")", controls);
    }

    public NamingEnumeration<SearchResult> keyed(HttpServletRequest request) throws Exception {
        Map<String, String> attrs = new HashMap<String, String>();
        attrs.put("lookup", "uid");
        attrs.put("user", request.getHeader("X-User"));
        String who = attrs.get("user");
~>        return ctx.search(BASE, "(uid=" + who + ")", controls);
    }

    public NamingEnumeration<SearchResult> managers(HttpServletRequest request) throws Exception {
        String manager = request.getParameter("manager");
        String filter = managerFilter(manager);
~>        return ctx.search(BASE, filter, controls);
    }

    private String managerFilter(String manager) {
        String prefix = "(manager=";
        return prefix + manager.toLowerCase() + ")";
    }
}
