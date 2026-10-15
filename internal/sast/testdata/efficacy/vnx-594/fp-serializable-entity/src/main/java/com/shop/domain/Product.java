package com.shop.domain;

import java.io.Serializable;
import javax.persistence.Entity;
import javax.enterprise.context.SessionScoped;

@Entity
public class Product implements Serializable {
    private static final long serialVersionUID = 1L;
}

@Entity
public class Tag
        implements java.io.Serializable, Comparable<Tag> {
    public int compareTo(Tag t) { return 0; }
}

@SessionScoped
public class Preferences implements Externalizable {
}

@Entity
public class Account implements UserDetails {
}

@Entity
public class Role implements GrantedAuthority, Comparable<Role> {
    public int compareTo(Role r) { return 0; }
}
