package com.acme.rules;

import jakarta.ejb.Singleton;

@Singleton
public class RuleCompiler {
    static final class BytesLoader extends ClassLoader {
        BytesLoader(ClassLoader parent) {
            super(parent);
        }

        Class<?> define(String name, byte[] code) {
~>            return defineClass(name, code, 0, code.length);
        }
    }

    public Class<?> compile(String name, byte[] code) {
~>        BytesLoader loader = new BytesLoader(RuleCompiler.class.getClassLoader());
        return loader.define(name, code);
    }
}
