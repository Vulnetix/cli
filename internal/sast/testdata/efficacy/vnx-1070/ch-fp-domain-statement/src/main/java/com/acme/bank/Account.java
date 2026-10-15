package com.acme.bank;

import java.io.Serializable;
import java.util.List;

public class Account implements Serializable {
    private static final long serialVersionUID = 7L;

    private String iban;
    private Statement lastStatement;
    private List<Statement> history;
}
