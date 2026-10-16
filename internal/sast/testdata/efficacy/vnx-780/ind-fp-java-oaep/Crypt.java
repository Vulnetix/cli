import javax.crypto.Cipher;
import java.security.Signature;

public class Crypt {
    Cipher make() throws Exception {
        return Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }
    Signature sig() throws Exception {
        return Signature.getInstance("SHA256withRSA");
    }
}
