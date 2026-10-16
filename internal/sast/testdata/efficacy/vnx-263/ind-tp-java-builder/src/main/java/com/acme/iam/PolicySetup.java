package com.acme.iam;

import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.UpdateAccountPasswordPolicyRequest;

public class PolicySetup {
    public static void apply(IamClient iam) {
        UpdateAccountPasswordPolicyRequest req = UpdateAccountPasswordPolicyRequest.builder()
                .minimumPasswordLength(14)
                .requireSymbols(true)
~>                .maxPasswordAge(1095)
                .build();
        iam.updateAccountPasswordPolicy(req);
    }
}
