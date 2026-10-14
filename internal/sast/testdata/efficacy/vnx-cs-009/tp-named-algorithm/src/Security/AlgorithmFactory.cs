using System.Security.Cryptography;

namespace Intranet.Security
{
    public static class AlgorithmFactory
    {
        public static HashAlgorithm LegacyDigest()
        {
~>            return HashAlgorithm.Create("MD5");
        }

        public static HashAlgorithm FromConfig()
        {
~>            return (HashAlgorithm)CryptoConfig.CreateFromName("SHA1");
        }

        public static SymmetricAlgorithm Cipher()
        {
~>            return SymmetricAlgorithm.Create( "TripleDES" );
        }

        public static object Qualified()
        {
~>            return CryptoConfig.CreateFromName("System.Security.Cryptography.MD5");
        }

        public static SymmetricAlgorithm Des()
        {
~>            return SymmetricAlgorithm.Create("DES");
        }

        public static object ShortName()
        {
            // CryptoConfig maps "SHA" to SHA-1.
~>            return CryptoConfig.CreateFromName("SHA");
        }

        public static HashAlgorithm Lower()
        {
~>            return HashAlgorithm.Create("sha1");
        }
    }
}
