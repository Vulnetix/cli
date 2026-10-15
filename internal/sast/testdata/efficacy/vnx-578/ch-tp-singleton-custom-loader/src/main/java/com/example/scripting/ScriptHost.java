package com.example.scripting;

import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;
import java.net.URL;
import java.net.URLClassLoader;

@Startup
@Singleton
public class ScriptHost {
    private ClassLoader scripts;

    public void reload(URL[] jars) {
~>        scripts = URLClassLoader.newInstance(jars, getClass().getClassLoader());
    }
}
