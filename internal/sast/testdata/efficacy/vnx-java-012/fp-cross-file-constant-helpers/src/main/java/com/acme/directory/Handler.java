package com.acme.directory;

import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;

public class Handler {
    private DirContext ctx;
    private final SearchControls controls = new SearchControls();

    public void sanitized(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Cleaner cleaner = new Cleaner();
        String value = cleaner.clean(param);
        ctx.search("ou=people,dc=acme,dc=com", "(&(objectClass=person)(uid=" + value + "))", controls);
    }

    public void sanitizedInline(HttpServletRequest request) throws Exception {
        Cleaner cleaner = new Cleaner();
        String value = cleaner.clean(request.getParameter("value"));
        ctx.search("ou=people,dc=acme,dc=com", "(&(objectClass=person)(uid=" + value + "))", controls);
    }

    public void settings() throws Exception {
        Settings settings = new Settings();
        String value = settings.name();
        ctx.search("ou=people,dc=acme,dc=com", "(&(objectClass=person)(uid=" + value + "))", controls);
        ctx.search("ou=people,dc=acme,dc=com", "(&(objectClass=person)(uid=" + Settings.fixed() + "))", controls);
        ctx.search("ou=people,dc=acme,dc=com", "(&(objectClass=person)(uid=" + settings.ext() + "))", controls);
    }

    public void storedLiteral() throws Exception {
        Slot slot = new Slot("report");
        String value = slot.value();
        ctx.search("ou=people,dc=acme,dc=com", "(&(objectClass=person)(uid=" + value + "))", controls);
    }

    public void chained(HttpServletRequest request) throws Exception {
        Settings settings = new Settings();
        Pad pad = new Pad();
        String value = pad.keep(pad.keep(settings.name()));
        ctx.search("ou=people,dc=acme,dc=com", "(&(objectClass=person)(uid=" + value + "))", controls);
        String second = new Cleaner().choose(request.getParameter("value"), "fixed");
        ctx.search("ou=people,dc=acme,dc=com", "(&(objectClass=person)(uid=" + second + "))", controls);
    }
}
