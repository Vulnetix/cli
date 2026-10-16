using System;
using System.Security.Cryptography;
using System.Text;

namespace Realtime.Gateway.Handshake
{
    public static class HandshakeHelpers
    {
        private const string WebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

        // RFC 6455 fixes SHA-1 for the Sec-WebSocket-Accept header.
        public static string ComputeSecWebSocketAccept(string clientKey)
        {
            var accept = SHA1.HashData(Encoding.ASCII.GetBytes(clientKey + WebSocketGuid));
            return Convert.ToBase64String(accept);
        }

        public static string GravatarUrl(string email)
        {
            var normalized = email.Trim().ToLowerInvariant();
            var hash = MD5.HashData(Encoding.UTF8.GetBytes(normalized));
            return $"https://www.gravatar.com/avatar/{Convert.ToHexString(hash).ToLowerInvariant()}?d=identicon";
        }

        public static int TotpCode(byte[] secret, long counter)
        {
            using var hmac = new HMACSHA1(secret);
            var counterBytes = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian) Array.Reverse(counterBytes);
            var h = hmac.ComputeHash(counterBytes);
            var offset = h[^1] & 0x0F;
            var binary = ((h[offset] & 0x7F) << 24) | (h[offset + 1] << 16) | (h[offset + 2] << 8) | h[offset + 3];
            return binary % 1_000_000;
        }

        public static byte[] WebhookSignature(byte[] secret, byte[] body)
        {
            using var mac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA1, secret);
            mac.AppendData(body);
            return mac.GetHashAndReset();
        }

        public static byte[] WrapKey(RSA rsa, byte[] key)
        {
            return rsa.Encrypt(key, RSAEncryptionPadding.OaepSHA1);
        }

        public static byte[] DerivePasswordHash(string password, byte[] salt)
        {
            using var kdf = new Rfc2898DeriveBytes(password, salt, 310_000, HashAlgorithmName.SHA256);
            return kdf.GetBytes(32);
        }
    }
}
