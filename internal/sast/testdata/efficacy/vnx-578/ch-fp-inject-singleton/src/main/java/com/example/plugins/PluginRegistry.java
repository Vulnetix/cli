package com.example.plugins;

import jakarta.inject.Singleton;
import java.net.URL;
import java.net.URLClassLoader;

/**
 * A CDI/JSR-330 singleton, not an Enterprise JavaBean: the EJB class-loader
 * restriction does not apply here.
 */
@Singleton
public class PluginRegistry {
    public ClassLoader open(URL[] jars) {
        return new URLClassLoader(jars, Thread.currentThread().getContextClassLoader());
    }
}
