package acl;

import java.util.UUID;

public class Check {
    private UUID ownerId;

    void guard(UUID currentUser) {
~>        if (ownerId == currentUser) {
            allow();
        }
    }
}
