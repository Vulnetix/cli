import java.security.SecureRandom;
import javax.crypto.spec.PBEKeySpec;
import org.mindrot.jbcrypt.BCrypt;

public class Kdf {
    private static final String SALT_COLUMN = "password_salt";

    public PBEKeySpec spec(char[] password) {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return new PBEKeySpec(password, salt, 310000, 256);
    }

    public String bcrypt(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(12));
    }

    public boolean check(String password, String stored) {
        return BCrypt.hashpw(password, stored).equals(stored);
    }
}
