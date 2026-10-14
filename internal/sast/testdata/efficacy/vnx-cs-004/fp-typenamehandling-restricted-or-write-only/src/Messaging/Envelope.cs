using Newtonsoft.Json;

namespace Messaging
{
    public class Envelope
    {
        private static readonly JsonSerializerSettings Settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.Auto,
            SerializationBinder = new KnownTypesBinder(new[] { typeof(OrderPlaced), typeof(OrderShipped) }),
        };

        public object Read(string json) => JsonConvert.DeserializeObject(json, Settings);
    }
}
