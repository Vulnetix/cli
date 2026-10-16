package com.acme.plugin;

public class Loader {
    public Plugin load(String className) throws Exception {
        Class<?> cls = Class.forName(className);
~>        Object o = cls.newInstance();
        return (Plugin) o;
    }
}
