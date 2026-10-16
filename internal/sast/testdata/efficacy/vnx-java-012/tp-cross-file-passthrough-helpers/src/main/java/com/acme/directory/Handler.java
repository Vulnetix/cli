package com.acme.directory;

import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;

public class Handler {
    private DirContext ctx;
    private final SearchControls controls = new SearchControls();

    public void echoed(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Echo echo = new Echo();
        String value = echo.same(param);
~>        ctx.search("ou=people,dc=acme,dc=com", "(&(objectClass=person)(uid=" + value + "))", controls);
~>        ctx.search("ou=people,dc=acme,dc=com", "(&(objectClass=person)(uid=" + echo.same(param) + "))", controls);
    }

    public void stored(HttpServletRequest request) throws Exception {
        Slot slot = new Slot(request.getParameter("value"));
        String value = slot.value();
~>        ctx.search("ou=people,dc=acme,dc=com", "(&(objectClass=person)(uid=" + value + "))", controls);
    }

    public void storedFromLocal(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Slot slot = new Slot(param);
~>        ctx.search("ou=people,dc=acme,dc=com", "(&(objectClass=person)(uid=" + slot.value() + "))", controls);
    }

    public void replaced(HttpServletRequest request) throws Exception {
        MutableSlot slot = new MutableSlot("report");
        slot.put(request.getParameter("value"));
        String value = slot.value();
~>        ctx.search("ou=people,dc=acme,dc=com", "(&(objectClass=person)(uid=" + value + "))", controls);
    }

    public void ambiguousClass(HttpServletRequest request) throws Exception {
        com.acme.directory.left.Names names = new com.acme.directory.left.Names();
        String param = request.getParameter("value");
        String value = names.pick(param);
~>        ctx.search("ou=people,dc=acme,dc=com", "(&(objectClass=person)(uid=" + value + "))", controls);
    }

    public void unknownClass(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        String value = Registry.lookup(param);
~>        ctx.search("ou=people,dc=acme,dc=com", "(&(objectClass=person)(uid=" + value + "))", controls);
    }

    public void chained(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Pad pad = new Pad();
        Echo echo = new Echo();
        String value = pad.keep(echo.same(param));
~>        ctx.search("ou=people,dc=acme,dc=com", "(&(objectClass=person)(uid=" + value + "))", controls);
    }

    public void secondArgument(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Cleaner cleaner = new Cleaner();
        String value = cleaner.choose("fixed", param);
~>        ctx.search("ou=people,dc=acme,dc=com", "(&(objectClass=person)(uid=" + value + "))", controls);
    }
}
