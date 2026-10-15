package com.example.plugins;

import java.net.URL;
import java.net.URLClassLoader;
import org.springframework.stereotype.Service;

@Service
public class Loader {
    public Object load(URL jar, String type) throws Exception {
        ClassLoader parent = Thread.currentThread().getContextClassLoader();
        try (URLClassLoader loader = new URLClassLoader(new URL[] {jar}, parent)) {
            return loader.loadClass(type).getDeclaredConstructor().newInstance();
        }
    }
}
