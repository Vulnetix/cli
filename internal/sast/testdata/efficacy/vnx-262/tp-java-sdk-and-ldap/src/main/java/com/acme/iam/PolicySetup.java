package com.acme.iam;

import javax.naming.directory.BasicAttribute;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.UpdateAccountPasswordPolicyRequest;

public class PolicySetup {
    public void apply(IamClient iam) {
~>        UpdateAccountPasswordPolicyRequest req = UpdateAccountPasswordPolicyRequest.builder()
            .minimumPasswordLength(14)
            .requireSymbols(true)
            .build();
        iam.updateAccountPasswordPolicy(req);
    }

    public BasicAttribute serviceAccountFlags() {
~>        return new BasicAttribute("userAccountControl", "66048");
    }
}
