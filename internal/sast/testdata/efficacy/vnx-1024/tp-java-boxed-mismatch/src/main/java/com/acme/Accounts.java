package com.acme;

import java.math.BigDecimal;
import java.util.UUID;

public class Accounts {
    private Long ownerId;
    private Integer status;
    private Double ratio;
    private UUID tenant;

    public boolean isRoot() {
~>        return ownerId.equals(0);
    }

    public boolean closed() {
~>        return status.equals(3L) || ratio.equals(1);
    }

    public boolean sameTenant(BigDecimal limit) {
~>        return tenant.equals("@@sample:0[0]00[0]00[0][-]0[0]00[-]00[0]0[-][0]00[0][-]0[0]00[0]00[0]00[0]0@@");
    }
}
