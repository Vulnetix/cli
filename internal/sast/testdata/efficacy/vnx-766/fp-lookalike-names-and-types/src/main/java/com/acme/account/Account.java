package com.acme.account;

import java.time.Instant;

public class Account {
    public boolean passwordExpired;
    public int tokenCount;
    public Instant passwordChangedAt;
    public String passwordHint;
    public String secretQuestionLabel;
    public String tokenUrl = "https://auth.acme.local/token";
    public String displayName;
}
