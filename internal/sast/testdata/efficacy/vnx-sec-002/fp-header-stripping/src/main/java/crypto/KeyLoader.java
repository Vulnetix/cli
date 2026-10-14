package crypto;

public final class KeyLoader {
    static String body(String pem) {
        return pem.replace("-----BEGIN PRIVATE KEY-----", "")
                  .replace("-----END PRIVATE KEY-----", "")
                  .replaceAll("\\s", "");
    }
}
