using MessagePack;
using MessagePack.Resolvers;

namespace App.Cache
{
    public class ProductCodec
    {
        private static readonly MessagePackSerializerOptions Options =
            MessagePackSerializerOptions.Standard.WithResolver(ContractlessStandardResolver.Instance);

        public Product Decode(byte[] payload)
        {
            return MessagePackSerializer.Deserialize<Product>(payload, Options);
        }

        public byte[] Encode(object value)
        {
            // Typeless is only used to write, never to read untrusted data here.
            return MessagePackSerializer.Typeless.Serialize(value);
        }
    }
}
