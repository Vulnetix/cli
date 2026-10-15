using Newtonsoft.Json;

namespace Worker.Contracts
{
    public class JobEnvelope
    {
        public string JobId { get; set; }

~>        [JsonProperty(TypeNameHandling = TypeNameHandling.Auto)]
        public object Payload { get; set; }

~>        [JsonProperty(ItemTypeNameHandling = TypeNameHandling.All)]
        public List<object> Steps { get; set; }

        [JsonProperty(TypeNameHandling = TypeNameHandling.None)]
        public object Metadata { get; set; }
    }
}
