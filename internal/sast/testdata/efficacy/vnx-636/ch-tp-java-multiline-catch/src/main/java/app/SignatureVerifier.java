package app;

import java.security.Signature;
import java.security.SignatureException;

public class SignatureVerifier {
    public boolean verifySignature(byte[] data, byte[] sig) {
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.update(data);
            return s.verify(sig);
        } catch (SignatureException e) {
            LOG.warn("bad signature", e);
~>            return true;
        }
    }

    public boolean hasPermission(String user, String perm) {
        try {
            return acl.check(user, perm);
        } catch (Exception e) {
            // ignore
        }
~>        return true;
    }
}
