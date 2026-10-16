package com.acme.files;

import java.io.FileInputStream;
import javax.servlet.http.HttpServletRequest;

public class Handler {

    public void echoed(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Echo echo = new Echo();
        String value = echo.same(param);
~>        new FileInputStream("/srv/data/" + value).close();
~>        new FileInputStream("/srv/data/" + echo.same(param)).close();
    }

    public void stored(HttpServletRequest request) throws Exception {
        Slot slot = new Slot(request.getParameter("value"));
        String value = slot.value();
~>        new FileInputStream("/srv/data/" + value).close();
    }

    public void storedFromLocal(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Slot slot = new Slot(param);
~>        new FileInputStream("/srv/data/" + slot.value()).close();
    }

    public void replaced(HttpServletRequest request) throws Exception {
        MutableSlot slot = new MutableSlot("report");
        slot.put(request.getParameter("value"));
        String value = slot.value();
~>        new FileInputStream("/srv/data/" + value).close();
    }

    public void ambiguousClass(HttpServletRequest request) throws Exception {
        com.acme.files.left.Names names = new com.acme.files.left.Names();
        String param = request.getParameter("value");
        String value = names.pick(param);
~>        new FileInputStream("/srv/data/" + value).close();
    }

    public void unknownClass(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        String value = Registry.lookup(param);
~>        new FileInputStream("/srv/data/" + value).close();
    }

    public void chained(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Pad pad = new Pad();
        Echo echo = new Echo();
        String value = pad.keep(echo.same(param));
~>        new FileInputStream("/srv/data/" + value).close();
    }

    public void secondArgument(HttpServletRequest request) throws Exception {
        String param = request.getParameter("value");
        Cleaner cleaner = new Cleaner();
        String value = cleaner.choose("fixed", param);
~>        new FileInputStream("/srv/data/" + value).close();
    }
}
