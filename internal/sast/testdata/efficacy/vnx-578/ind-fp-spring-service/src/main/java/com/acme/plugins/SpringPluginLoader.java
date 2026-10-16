package com.acme.plugins;

import java.net.URL;
import java.net.URLClassLoader;
import org.springframework.stereotype.Service;

@Service
public class SpringPluginLoader {
    public Class<?> load(URL jar, String name) throws Exception {
        ClassLoader parent = Thread.currentThread().getContextClassLoader();
        URLClassLoader loader = new URLClassLoader(new URL[] {jar}, parent);
        return loader.loadClass(name);
    }
}
