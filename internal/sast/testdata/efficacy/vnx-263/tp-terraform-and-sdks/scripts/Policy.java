package scripts;

import software.amazon.awssdk.services.iam.model.UpdateAccountPasswordPolicyRequest;

class Policy {
    UpdateAccountPasswordPolicyRequest req() {
        return UpdateAccountPasswordPolicyRequest.builder()
            .minimumPasswordLength(14)
~>            .maxPasswordAge(1095)
            .build();
    }
}
