package com.acme.plugin;

import javax.servlet.http.HttpServletRequest;

public class PluginLoader {
    public Plugin load(HttpServletRequest request) throws Exception {
        String impl = request.getHeader("X-Plugin-Impl");
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
~>        Class<?> c = cl.loadClass(impl);
        return (Plugin) c.getDeclaredConstructor().newInstance();
    }
}
