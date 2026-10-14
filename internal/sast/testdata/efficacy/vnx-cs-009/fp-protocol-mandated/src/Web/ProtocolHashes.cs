using System;
using System.Security.Cryptography;
using System.Text;

namespace Forum.Web
{
    public static class ProtocolHashes
    {
        private const string WebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

        // RFC 6455 fixes SHA-1 for the opening handshake.
        public static string SecWebSocketAccept(string clientKey)
        {
            var hash = SHA1.HashData(Encoding.ASCII.GetBytes(clientKey + WebSocketGuid));
            return Convert.ToBase64String(hash);
        }

        public static string GravatarUrl(string email)
        {
            var normalized = email.Trim().ToLowerInvariant();
            var hash = MD5.HashData(Encoding.UTF8.GetBytes(normalized));
            return $"https://www.gravatar.com/avatar/{Convert.ToHexString(hash).ToLowerInvariant()}";
        }

        public static string ETagFor(byte[] body)
        {
            using var md5 = MD5.Create();
            var etag = Convert.ToBase64String(md5.ComputeHash(body));
            return $"\"{etag}\"";
        }

        public static void SetContentMd5(BlobHeaders headers, byte[] content)
        {
            headers.ContentHash = MD5.HashData(content);
        }

        public static Guid NameBasedGuid(string name)
        {
            var bytes = SHA1.HashData(Encoding.UTF8.GetBytes(name));
            var g = new byte[16];
            Array.Copy(bytes, g, 16);
            g[6] = (byte)((g[6] & 0x0F) | 0x50);
            return new Guid(g);
        }
    }

    public sealed class BlobHeaders
    {
        public byte[] ContentHash { get; set; } = Array.Empty<byte>();
    }
}
