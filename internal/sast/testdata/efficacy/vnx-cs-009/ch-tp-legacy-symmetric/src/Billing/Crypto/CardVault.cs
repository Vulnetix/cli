using System;
using System.IO;
using System.Security.Cryptography;

namespace Billing.Crypto
{
    internal sealed class CardVault
    {
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public CardVault(byte[] key, byte[] iv)
        {
            _key = key;
            _iv = iv;
        }

        public byte[] EncryptPan(byte[] pan)
        {
~>            using (var des = new DESCryptoServiceProvider())
            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, des.CreateEncryptor(_key, _iv), CryptoStreamMode.Write))
                {
                    cs.Write(pan, 0, pan.Length);
                }
                return ms.ToArray();
            }
        }

        public ICryptoTransform LegacyDecryptor()
        {
~>            SymmetricAlgorithm alg = TripleDES.Create();
            alg.Key = _key;
            alg.IV = _iv;
            return alg.CreateDecryptor();
        }

        public ICryptoTransform Rc2Transform()
        {
~>            var rc2 = new @@sample:R[C]2C[r]yp[t]oS[e]rv[i]ce[P]ro[v]id[e]r@@ { Key = _key, IV = _iv };
            return rc2.CreateEncryptor();
        }

        public ICryptoTransform Mainframe()
        {
~>            var tdes = new TripleDESCryptoServiceProvider
            {
                Key = _key,
                Mode = CipherMode.CBC,
            };
            return tdes.CreateEncryptor();
        }
    }
}
