package com.acme.plugins;

import java.net.URL;
import java.net.URLClassLoader;
import javax.ejb.Stateless;
import org.junit.jupiter.api.Test;

@Stateless
class PluginServiceTest {
    @Test
    void loadsFromJar() throws Exception {
        URL jar = getClass().getClassLoader().getResource("plugin.jar");
        try (URLClassLoader l = new URLClassLoader(new URL[] {jar})) {
            l.loadClass("com.acme.Plugin");
        }
    }
}
