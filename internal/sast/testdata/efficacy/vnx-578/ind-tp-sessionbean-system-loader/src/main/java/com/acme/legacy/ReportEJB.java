package com.acme.legacy;

import javax.ejb.SessionBean;
import javax.ejb.SessionContext;

public class ReportEJB implements SessionBean {
    private SessionContext ctx;

    public Class<?> rendererFor(String name) throws ClassNotFoundException {
~>        ClassLoader sys = ClassLoader.getSystemClassLoader();
        return sys.loadClass(name);
    }

    public void setSessionContext(SessionContext c) { this.ctx = c; }
    public void ejbRemove() { }
    public void ejbActivate() { }
    public void ejbPassivate() { }
}
