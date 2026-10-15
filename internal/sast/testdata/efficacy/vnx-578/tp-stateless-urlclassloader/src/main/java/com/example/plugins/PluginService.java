package com.example.plugins;

import java.net.URL;
import java.net.URLClassLoader;
import javax.ejb.Stateless;

@Stateless
public class PluginService {
    public Object load(URL jar, String type) throws Exception {
~>        try (URLClassLoader loader = new URLClassLoader(new URL[] {jar})) {
            return loader.loadClass(type).getDeclaredConstructor().newInstance();
        }
    }
}
