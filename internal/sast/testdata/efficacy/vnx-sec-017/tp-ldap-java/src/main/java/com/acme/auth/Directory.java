package com.acme.auth;

import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.directory.InitialDirContext;

public class Directory {
    public InitialDirContext connect(String user, String password) throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
~>        env.put(Context.PROVIDER_URL, "ldap://dc01.corp.acme.com:389");
        env.put(Context.SECURITY_PRINCIPAL, user);
        env.put(Context.SECURITY_CREDENTIALS, password);
        return new InitialDirContext(env);
    }
}
