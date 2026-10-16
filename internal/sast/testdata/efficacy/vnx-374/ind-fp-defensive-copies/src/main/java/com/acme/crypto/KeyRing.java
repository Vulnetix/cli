package com.acme.crypto;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class KeyRing {
    private final byte[] master;
    private final byte[] salt;
    private final Date notAfter;
    private final List<String> owners;
    private final Map<String, byte[]> wrapped;
    private Set<String> scopes;

    public KeyRing(byte[] master, byte[] salt, Date notAfter, List<String> owners,
                   Map<String, byte[]> wrapped) {
        this.master = master.clone();
        this.salt = Arrays.copyOf(salt, salt.length);
        this.notAfter = new Date(notAfter.getTime());
        this.owners = new ArrayList<>(owners);
        this.wrapped = Collections.unmodifiableMap(wrapped);
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = Set.copyOf(scopes);
    }

    public void setOwnerCount(List<String> owners) {
        this.ownerCount = owners.size();
    }

    private int ownerCount;
}
