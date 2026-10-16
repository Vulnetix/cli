package com.acme.files;

import java.io.FileInputStream;
import javax.servlet.http.HttpServletRequest;

public class Handler {

    public void sanitized(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Cleaner cleaner = new Cleaner();
        String value = cleaner.clean(param);
        new FileInputStream("/srv/data/" + value).close();
    }

    public void sanitizedInline(HttpServletRequest request) throws Exception {
        Cleaner cleaner = new Cleaner();
        String value = cleaner.clean(request.getParameter("value"));
        new FileInputStream("/srv/data/" + value).close();
    }

    public void settings() throws Exception {
        Settings settings = new Settings();
        String value = settings.name();
        new FileInputStream("/srv/data/" + value).close();
        new FileInputStream("/srv/data/" + Settings.fixed()).close();
        new FileInputStream("/srv/data/" + settings.ext()).close();
    }

    public void storedLiteral() throws Exception {
        Slot slot = new Slot("report");
        String value = slot.value();
        new FileInputStream("/srv/data/" + value).close();
    }

    public void chained(HttpServletRequest request) throws Exception {
        Settings settings = new Settings();
        Pad pad = new Pad();
        String value = pad.keep(pad.keep(settings.name()));
        new FileInputStream("/srv/data/" + value).close();
        String second = new Cleaner().choose(request.getParameter("value"), "fixed");
        new FileInputStream("/srv/data/" + second).close();
    }
}
