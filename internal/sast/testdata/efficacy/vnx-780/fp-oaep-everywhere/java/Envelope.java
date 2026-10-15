import javax.crypto.Cipher;
import java.security.Signature;
import java.security.KeyPairGenerator;

class Envelope {
    byte[] wrap(java.security.PublicKey pub, byte[] k) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/@@sample:O[A]EP[W]it[h]SH[A][-]2[5]6A[n]dM[G]F1[P]ad[d]in[g]@@");
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        Signature s = Signature.getInstance("SHA256withRSA");
        c.init(Cipher.ENCRYPT_MODE, pub);
        return c.doFinal(k);
    }

    Cipher fromConfig(String transformation) throws Exception {
        return Cipher.getInstance(transformation);
    }
}
