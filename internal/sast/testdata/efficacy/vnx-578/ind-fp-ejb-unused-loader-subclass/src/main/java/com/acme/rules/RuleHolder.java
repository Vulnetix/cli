package com.acme.rules;

import javax.ejb.Stateless;

@Stateless
public class RuleHolder {
    static final class ReservedLoader extends ClassLoader {
        ReservedLoader(ClassLoader parent) {
            super(parent);
        }
    }

    public int count() {
        return 0;
    }
}
