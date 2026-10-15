package com.acme.model;

import java.io.Serial;
import java.io.Serializable;

public class Invoice implements Serializable {
    @Serial
    private static final long serialVersionUID = -4213901238471L;

    private long total;
}
