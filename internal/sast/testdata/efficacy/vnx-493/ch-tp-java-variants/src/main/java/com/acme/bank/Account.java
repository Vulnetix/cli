package com.acme.bank;

public class Account {
~>    public long balance;
~>    public double amount = 0.0;
~>    public boolean admin;
~>    public transient String sessionToken;
    private String owner;
}
