package com.acme.session;

import java.io.Serializable;
import java.util.logging.Logger;
import com.fasterxml.jackson.annotation.JsonIgnore;

public class UserSession implements Serializable {
    private static final long serialVersionUID = 1L;

    private String userId;
~>    @JsonIgnore private Logger auditLog = Logger.getLogger("audit");
}
