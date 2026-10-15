using MessagePack;
using MessagePack.Resolvers;

namespace App.Cache
{
    public class DistributedCacheCodec
    {
        public object Decode(byte[] payload)
        {
~>            return MessagePackSerializer.Typeless.Deserialize(payload);
        }

        public T DecodeAs<T>(byte[] payload)
        {
            var options = MessagePackSerializerOptions.Standard
~>                .WithResolver(TypelessContractlessStandardResolver.Instance);
            return MessagePackSerializer.Deserialize<T>(payload, options);
        }
    }
}
