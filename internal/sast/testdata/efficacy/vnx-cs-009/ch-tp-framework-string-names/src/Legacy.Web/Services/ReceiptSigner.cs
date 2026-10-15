using System.Security.Cryptography;

namespace Legacy.Web.Services
{
    public class ReceiptSigner
    {
        private readonly RSACryptoServiceProvider _rsa;

        public ReceiptSigner(RSACryptoServiceProvider rsa)
        {
            _rsa = rsa;
        }

        public byte[] Sign(byte[] receipt)
        {
~>            return _rsa.SignData(receipt, "SHA1");
        }

        public bool Check(byte[] receipt, byte[] signature)
        {
~>            return _rsa.VerifyData(receipt, "MD5", signature);
        }

        public byte[] SignDigest(byte[] digest)
        {
~>            return _rsa.SignHash(digest, CryptoConfig.MapNameToOID("SHA1"));
        }

        public byte[] SignWithObject(byte[] receipt)
        {
~>            return _rsa.SignData(receipt, new @@sample:S[H]A1[C]ry[p]to[S]er[v]ic[e]Pr[o]vi[d]er@@());
        }

        public byte[] Strong(byte[] receipt)
        {
            return _rsa.SignData(receipt, "SHA256");
        }
    }
}
