package com.example.boot;

import com.google.inject.Singleton;
import jakarta.enterprise.context.ApplicationScoped;

@Singleton
public class ModuleLoader {
    public Class<?> load(String name) throws ClassNotFoundException {
        return Class.forName(name, false, ModuleLoader.class.getClassLoader());
    }
}

@ApplicationScoped
class Resources {
    // "@Stateless beans must not call getContextClassLoader()" is a rule for EJBs.
    ClassLoader loader() {
        return Thread.currentThread().getContextClassLoader();
    }
}
