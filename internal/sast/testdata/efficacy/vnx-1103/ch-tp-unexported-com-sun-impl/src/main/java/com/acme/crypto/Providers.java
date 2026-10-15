package com.acme.crypto;

~>import com.sun.crypto.provider.SunJCE;
~>import com.sun.jndi.ldap.LdapCtxFactory;
import java.security.Security;

public final class Providers {
    public static void install() {
        Security.addProvider(new SunJCE());
    }
}
