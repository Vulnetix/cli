using System.Security.Cryptography;
class Enc {
    static byte[] Seal(RSA rsa, byte[] d) {
~>        return rsa.Encrypt(d, false);
    }
}
