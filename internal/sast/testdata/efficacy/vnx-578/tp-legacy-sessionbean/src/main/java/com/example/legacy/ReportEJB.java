package com.example.legacy;

import javax.ejb.SessionBean;
import javax.ejb.SessionContext;

public class ReportEJB implements SessionBean {
    private SessionContext ctx;

    public Class<?> renderer(byte[] code) {
~>        return new ReportLoader().defineClass("com.example.Renderer", code);
    }

    static class ReportLoader extends ClassLoader {
        Class<?> defineClass(String name, byte[] b) {
~>            return defineClass(name, b, 0, b.length);
        }
    }

    public void setSessionContext(SessionContext c) { this.ctx = c; }
    public void ejbActivate() {}
    public void ejbPassivate() {}
    public void ejbRemove() {}
}
