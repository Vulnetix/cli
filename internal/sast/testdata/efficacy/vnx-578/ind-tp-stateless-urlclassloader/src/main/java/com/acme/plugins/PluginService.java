package com.acme.plugins;

import java.net.URL;
import java.net.URLClassLoader;
import javax.ejb.Stateless;

@Stateless
public class PluginService {
    public Object instantiate(URL jar, String className) throws Exception {
~>        try (URLClassLoader loader = new URLClassLoader(new URL[] {jar}, null)) {
            Class<?> type = loader.loadClass(className);
            return type.getDeclaredConstructor().newInstance();
        }
    }
}
