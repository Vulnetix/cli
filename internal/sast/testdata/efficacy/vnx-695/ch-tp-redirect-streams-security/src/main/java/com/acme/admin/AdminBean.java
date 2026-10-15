package com.acme.admin;

import java.io.PrintStream;
import java.net.URL;
import java.net.URLClassLoader;
import javax.ejb.Singleton;

@Singleton
public class AdminBean {

    public void quiet(PrintStream sink) {
~>        System.setOut(sink);
~>        System.setSecurityManager(null);
    }

    public ClassLoader plugins(URL[] urls) {
~>        return new URLClassLoader(urls);
    }
}
