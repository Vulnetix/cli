package com.acme.auth;

import java.util.Date;
import java.util.Set;
import java.util.TreeSet;

public final class Grant {
    private final TreeSet<String> scopes = new TreeSet<>();
    private Date expires;

~>    public Set<String> getScopes() { return scopes; }

~>    public Date getExpires() { return this.expires; }

    public boolean isExpired(Date now) { return expires != null && now.after(expires); }
}
