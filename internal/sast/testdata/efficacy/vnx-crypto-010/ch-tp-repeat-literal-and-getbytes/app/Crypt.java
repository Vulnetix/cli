package app;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
public class Crypt {
    public byte[] enc(byte[] key, byte[] data, javax.crypto.SecretKey k) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec("0123456789abcdef".getBytes("UTF-8")));
        return c.doFinal(data);
    }
}
