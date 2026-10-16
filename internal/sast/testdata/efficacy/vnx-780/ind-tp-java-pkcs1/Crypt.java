import javax.crypto.Cipher;
import java.security.PublicKey;

public class Crypt {
    byte[] enc(PublicKey k, byte[] d) throws Exception {
~>        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.ENCRYPT_MODE, k);
        return c.doFinal(d);
    }
}
