package com.example.plugins;

import javax.ejb.Stateless;
import org.junit.jupiter.api.Test;

@Stateless
class PluginServiceTest {
    @Test
    void loads() {
        ClassLoader cl = getClass().getClassLoader();
        cl.getResource("plugin.jar");
    }
}
