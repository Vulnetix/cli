package com.acme.pki;

import java.io.InputStream;
import java.security.KeyStore;

public class KeyExporter {

    private final AuditLog audit;

    public KeyExporter(AuditLog audit) {
        this.audit = audit;
    }

    public ExportBundle export(InputStream in, char[] storePassword, String alias) throws Exception {
        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(storePassword);
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(in, protection.getPassword());
        KeyStore.Entry entry = ks.getEntry(alias, protection);
~>        String exportPassphrase = String.copyValueOf(protection.getPassword());
        audit.record("export", alias);
        return new ExportBundle(entry, exportPassphrase);
    }
}
